I made the fix to `modules/mod-004-network-security/exercise-04-rate-limit-ddos-design/SOLUTION.md` (line 27–29): rewrote the wrapped bullet so it no longer starts with `  + admission control`, which MD004 was flagging as a nested `+`-style list item. Verified no other `+` bullets remain in the file.

The edit is in the working tree but unstaged — `git add`/`commit`/`push` require approval, which was declined. You can finish with:

```
git add modules/mod-004-network-security/exercise-04-rate-limit-ddos-design/SOLUTION.md
git commit -m "Fix MD004 lint: reflow plus-prefixed continuation line"
git push
```
