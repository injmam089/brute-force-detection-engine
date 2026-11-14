# Firewall Ban List Suggestions

These commands are suggestions only. An authorized administrator must review, validate, and approve them before any use. This tool never executes firewall commands.
UFW and iptables are alternative firewall tools; choose the format appropriate to the host rather than applying both suggestions.

## 203.0.113.10

- Severity: HIGH
- UFW suggestion:

```bash
sudo ufw deny from 203.0.113.10 to any
```

- iptables suggestion:

```bash
sudo iptables -I INPUT 1 -s 203.0.113.10 -j DROP
```
