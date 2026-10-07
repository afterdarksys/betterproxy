# betterproxy cloud policy
#
# Scores every message against the betterspam/betterphish cloud, stamps the
# verdict into headers, and acts on the cloud's recommendation. Fails OPEN: if
# the cloud is unreachable the message is accepted and marked as unscored, so a
# cloud outage never blocks mail. Optionally contributes the message to the
# betterphish feed.
#
# Run: betterproxy proxy --script=examples/betterproxy-cloud.star \
#        --upstream=mail-internal:25 \
#        --cloud-check-url=https://betterspam.com/api/v1/mail/check \
#        --cloud-submit-url=https://www.betterphish.io/api/v1/submit/email \
#        --cloud-privacy=full
#      (API key via env BETTERPROXY_CLOUD_TOKEN)

def evaluate():
    # 1. Strip the ENTIRE verdict namespaces so a sender cannot forge any
    #    header we (or downstream filters) might trust — not just the names we
    #    restamp below. We only trust headers we stamp ourselves, afterward.
    remove_header_prefix("X-BetterSpam-")
    remove_header_prefix("X-BetterPhish-")
    remove_header_prefix("X-BetterProxy-")

    if not cloud_available():
        add_header("X-BetterProxy-Cloud", "disabled")
        accept()
        return

    # 2. Synchronous verdict. betterspam_check also folds the spam score into
    #    the running message score (score=True by default).
    v = betterspam_check()

    # 3. Fail open on cloud trouble.
    if not v["cloud_ok"]:
        log_entry("betterproxy: cloud degraded: " + v["reason"])
        add_header("X-BetterProxy-Cloud", "unavailable")
        accept()
        return

    # 4. Stamp the verdict (headers added above the body; body is never
    #    rewritten, so DKIM on pass-through stays intact).
    is_spam = "Yes" if v["is_spam"] else "No"
    add_header("X-BetterSpam-Status",
               is_spam + ", score=" + str(v["spam_score"]) +
               ", required=" + str(v["max_score"]) + ", verdict=" + v["verdict"])
    add_header("X-BetterPhish-Verdict",
               ("phish" if v["is_phishing"] else "clean") +
               ", confidence=" + str(v["confidence"]))
    add_header("X-BetterProxy-Action", v["action"])
    add_header("X-BetterProxy-Cloud", "ok")

    # 5. Contribute to the betterphish feed (async, best-effort).
    betterphish_submit()

    # 6. Act on the cloud recommendation.
    log_entry("betterproxy: verdict=" + v["verdict"] + " action=" + v["action"])
    if v["action"] == "reject":
        reject()
        return
    if v["action"] == "quarantine":
        quarantine()
        return
    accept()
