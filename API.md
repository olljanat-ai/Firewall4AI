## API Reference
### Skills
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/skills` | List all skills |
| `POST` | `/api/skills` | Create a skill (ID auto-generated if omitted, token is GUID) |
| `PUT` | `/api/skills` | Update a skill |
| `DELETE` | `/api/skills?id=<id>` | Delete a skill |

### Approvals
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/approvals` | List all approvals |
| `GET` | `/api/approvals/pending` | List pending approvals |
| `POST` | `/api/approvals/decide` | Approve or deny a host (empty `skill_id` + empty `source_ip` = global, empty `skill_id` + `source_ip` = VM-specific) |

### Image Approvals (Container Registry)
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/images` | List all image approvals |
| `GET` | `/api/images/pending` | List pending image approvals |
| `POST` | `/api/images/decide` | Approve or deny an image (same level semantics as host approvals) |
| `DELETE` | `/api/images` | Delete an image approval rule |

### Credentials
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/credentials` | List credentials (secrets masked) |
| `POST` | `/api/credentials` | Add a credential |
| `PUT` | `/api/credentials` | Update a credential |
| `DELETE` | `/api/credentials?id=<id>` | Delete a credential |

### Logs
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/logs?limit=100` | Get recent log entries |
| `GET` | `/api/logs?after=<id>` | Get log entries after a given ID |
| `GET` | `/api/logs/stats` | Get log statistics |

### Other
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/ca.crt` | Download CA certificate |
