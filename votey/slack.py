import hashlib
import hmac
import json
import shlex
import time
import uuid
from typing import Any
from typing import List
from typing import Optional
from typing import Tuple

import requests
from flask import Blueprint
from flask import current_app
from flask import jsonify
from flask import request

from .models import Option
from .models import Poll
from .models import Vote
from .models import Workspace
from .utils import AnyJSON
from .utils import batch
from .utils import get_footer
from .utils import JSON
from votey import db

bp = Blueprint("slack", __name__)

NUM_TO_SLACKMOJI = {
    1: ":one:",
    2: ":two:",
    3: ":three:",
    4: ":four:",
    5: ":five:",
    6: ":six:",
    7: ":seven:",
    8: ":eight:",
    9: ":nine:",
    10: ":keycap_ten:",
}

ANON_KEYWORDS = {
    "--anonymous",
    "-anonymous",
    "-anon",
    "--anon",
}

SECRET_KEYWORDS = {
    "--secret",
    "-secret",
}


@bp.route("/slack", methods=["POST"])
def slack() -> Any:
    return (
        handle_button_interaction(request.form)
        if valid_request(request) and request.form.get("payload")
        else handle_poll_creation(request.form)
        if valid_request(request)
        else ""
    )


@bp.route("/oauth", methods=["GET"])
def oauth() -> str:
    code = request.args.get("code")
    client_id = current_app.config["CLIENT_ID"]
    client_secret = current_app.config["CLIENT_SECRET"]
    oauth = requests.get(
        "https://slack.com/api/oauth.access",
        params={"code": code, "client_id": client_id, "client_secret": client_secret},  # type: ignore
    )
    if oauth.json().get("ok"):
        team_id = oauth.json().get("team_id")
        token = oauth.json().get("access_token")
        name = oauth.json().get("team_name")
        workspace = Workspace.query.filter_by(team_id=team_id).first()
        if workspace is not None:
            workspace.token = token
        else:
            workspace = Workspace(team_id, name, token)
            db.session.add(workspace)
        db.session.commit()
        return f"thanks! votey has been installed to <b>{name}</b>. you can close this tab."
    return "something went wrong :("


def handle_poll_creation(req: JSON) -> Any:
    current_app.logger.debug("creating poll with json {}".format(req))
    workspace = Workspace.query.filter_by(team_id=req.get("team_id")).first()
    command, anonymous, secret = get_command_from_req(req, workspace)
    if command is None:
        return ""

    channel = req.get("channel_id", "")

    poll_question = command.pop(0)
    actions = []
    fields = []

    poll = Poll(uuid.uuid4(), poll_question, channel, anonymous, secret)
    db.session.add(poll)
    db.session.commit()

    # write the poll question and a divider to the blocks list
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": poll_question}},
        {"type": "divider"},
    ]

    for counter, option_text in enumerate(command):
        option = Option(poll.id, option_text)
        db.session.add(option)
        db.session.commit()

        actions.append(
            {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": NUM_TO_SLACKMOJI[counter + 1],
                    "emoji": True,
                },
                "action_id": str(option.id) + "?" + str(counter),
                "value": str(poll.poll_identifier()),
            }
        )
        fields.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{NUM_TO_SLACKMOJI[counter + 1]} {option_text}\n\n\n",
                },
            }
        )

    # write options to the blocks list
    blocks.extend(fields)

    # write the footer to the blocks list
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": get_footer(req.get("user_id", ""), anonymous, secret),
                }
            ],
        }
    )

    # batch actions in groups of 5 so Slack does not hide them in a context menu
    for batched in batch(actions, 5):
        blocks.append({"type": "actions", "elements": batched})

    current_app.logger.debug("writing poll to channel {}".format(channel))
    res = send_message(workspace, channel, blocks=blocks).json()
    current_app.logger.debug("got poll creation response: {}".format(res))

    # if the poll creation was successful
    if "ts" in res:
        poll.ts = res["ts"]
        db.session.commit()

        delete_attachment = {
            "text": " ",
            "callback_id": poll.poll_identifier(),
            "actions": [
                {
                    "name": "delete",
                    "text": "Delete",
                    "type": "button",
                    "style": "danger",
                }
            ],
        }
        send_message(
            workspace,
            req.get("user_id", ""),
            text=f'Delete your last poll, "{poll_question}"?',
            attachments=[delete_attachment],
        )
    else:
        body = {
            "response_type": "in_channel",
            "text": " ",
            "blocks": blocks,
        }
        current_app.logger.debug("DIRECTLY returning {}".format(body))
        return jsonify(body)
    return ""


def handle_button_interaction(req: JSON) -> Any:
    res = json.loads(req.get("payload", ""))
    # import pdb;pdb.set_trace()
    # button = res.get("actions")[0]["name"]
    # return handle_poll_deletion(res) if button == "delete" else handle_vote(res)
    return handle_vote(res)


def handle_vote(response: AnyJSON) -> Any:
    current_app.logger.debug("handling vote with req {}".format(response))
    option_id, position = response.get("actions", [])[0]["action_id"].split("?")
    position = int(position)

    poll = Poll.query.filter_by(identifier=response.get("actions")[0]["value"]).first()
    option = Option.query.filter_by(id=option_id).first()

    user = response.get("user", {}).get("id")
    original_message = response.get("message", {})

    if poll is not None and option is not None:
        vote = Vote.query.filter_by(
            poll_id=poll.id, option_id=option.id, user=user
        ).first()

        if vote:
            db.session.delete(vote)
        else:
            vote = Vote(poll.id, option.id, user)
            db.session.add(vote)
        db.session.commit()

        votes = Vote.query.filter_by(option_id=option.id).all()
        num = f"`{len(votes)}`"
        field_text = (
            f"{NUM_TO_SLACKMOJI[position+1]} {option.option_text}\t"
            f'{num if votes else ""}\n'
            f"{thumbs(votes) if poll.anonymous else names(votes)}\n\n"
        )

        original_message.get("blocks")[position + 2]["text"]["text"] = field_text
        import pdb

        pdb.set_trace()
        return jsonify(original_message)
    return ""


def handle_poll_deletion(response: AnyJSON) -> str:
    workspace = Workspace.query.filter_by(
        team_id=response.get("team", {}).get("id")
    ).first()
    poll = Poll.query.filter_by(identifier=response.get("callback_id")).first()
    Vote.query.filter_by(poll_id=poll.id).delete()
    Option.query.filter_by(poll_id=poll.id).delete()

    db.session.delete(poll)
    db.session.commit()

    requests.post(
        "https://slack.com/api/chat.delete",
        json={"channel": poll.channel, "ts": poll.ts},
        headers={"Authorization": f"Bearer {workspace.token}"},
    )
    return f'Your poll "{poll.question}" has been deleted.'


def thumbs(votes: List[Vote]) -> str:
    return ":thumbsup:" * len(votes)


def names(votes: List[Vote]) -> str:
    return ",".join([f"<@{vote.user}>" for vote in votes])


def valid_request(request: Any) -> bool:
    timestamp = request.headers["X-Slack-Request-Timestamp"]
    slack_signature = request.headers["X-Slack-Signature"]

    # Avoid replay attacks
    if abs(time.time() - int(timestamp)) > (60 * 5):
        return False
    sig_basestring = str.encode(f"v0:{timestamp}:") + request.get_data()
    request_hash = (
        "v0="
        + hmac.new(
            bytes(current_app.config["SIGNING_SECRET"], encoding="utf-8"),
            sig_basestring,
            hashlib.sha256,
        ).hexdigest()
    )
    return hmac.compare_digest(request_hash, slack_signature)


def get_command_from_req(
    request: JSON, workspace: Workspace
) -> Tuple[Optional[List[str]], bool, bool]:
    try:
        split = shlex.split(request.get("text", "").replace("“", '"').replace("”", '"'))
    except ValueError as e:
        send_ephemeral_message(
            workspace,
            request.get("channel_id", ""),
            request.get("user_id", ""),
            f"We had trouble parsing that - {e}",
        )
        return None, False, False

    if ANON_KEYWORDS.isdisjoint(split):
        anonymous = False
    else:
        anonymous = True
        split = [word for word in split if word not in ANON_KEYWORDS]

    if SECRET_KEYWORDS.isdisjoint(split):
        secret = False
    else:
        secret = True
        anonymous = True
        split = [word for word in split if word not in SECRET_KEYWORDS]

    if len(split) < 2:
        send_ephemeral_message(
            workspace,
            request.get("channel_id", ""),
            request.get("user_id", ""),
            "Oops - a poll needs to have at least one option. "
            'Try again with `/votey "question" "option 1"`',
        )
        return None, False, False
    if len(split) > 11:
        send_ephemeral_message(
            workspace,
            request.get("channel_id", ""),
            request.get("user_id", ""),
            "Sorry - Votey only supports 10 options at the moment.",
        )
        return None, False, False

    return split, anonymous, secret


def send_ephemeral_message(
    workspace: Workspace, channel: str, user: str, text: str,
) -> requests.Response:
    return requests.post(
        "https://slack.com/api/chat.postEphemeral",
        json={"channel": channel, "user": user, "text": text},
        headers={"Authorization": f"Bearer {workspace.token}"},
    )


def send_message(
    workspace: Workspace,
    dest: str,
    text: Optional[str] = None,
    attachments: Optional[List[Any]] = None,
    blocks: Optional[List[Any]] = None,
) -> requests.Response:
    body: Any = {"channel": dest}
    if text is not None:
        body["text"] = text
    if attachments is not None:
        body["attachments"] = attachments
    if blocks is not None:
        body["blocks"] = blocks
    return requests.post(
        "https://slack.com/api/chat.postMessage",
        json=body,
        headers={"Authorization": f"Bearer {workspace.token}"},
    )
