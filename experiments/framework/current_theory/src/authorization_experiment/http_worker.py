"""One HTTP attempt; parent enforces a deadline by terminating this process.

Secrets arrive on stdin, never as command arguments or files. Only the parent
retains and redacts response data. No retry occurs in this worker.
"""

import json
import socket
import sys
from http.client import HTTPException, IncompleteRead
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main():
    task = json.load(sys.stdin)
    req = Request(task["url"], data=task["body"].encode("utf-8"), method="POST", headers={
        "Content-Type": "application/json", "Authorization": "Bearer " + task["key"]})
    result = {"code": None, "raw": "", "transport": None}
    try:
        try:
            response = urlopen(req, timeout=task["socket_timeout"])
        except HTTPError as exc:
            response = exc
        with response:
            result["code"] = response.code
            raw = response.read(task["response_limit"] + 1)
            if len(raw) > task["response_limit"]:
                result["transport"] = "response_size_exceeded_no_redraw"
            result["raw"] = raw[:task["response_limit"]].decode("utf-8", errors="replace")
    except IncompleteRead as exc:
        result.update(raw=exc.partial.decode("utf-8", errors="replace"), transport="incomplete_http_response")
    except (URLError, OSError, socket.timeout, HTTPException):
        result["transport"] = "network_or_timeout"
    print(json.dumps(result))


if __name__ == "__main__":
    main()
