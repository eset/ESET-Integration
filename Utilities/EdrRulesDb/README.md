# Edr Rules Db

### Get all available edr rules from connect api and store them into json file

### Environment Variables Config

| Value      | Description                                                                                          |
|------------|------------------------------------------------------------------------------------------------------|
| DB_DIR     | Path where to store edr_rules_db.json. If not set current working dir is used                        |
| HOST       | Incident management host. Set https://eu.incident-management.eset.systems by default                 |
| TOKEN_HOST | Business account host for getting token. Set https://eu.business-account.iam.eset.systems by default |
| USERNAME   | Eset Connect Username - required                                                                     |
| PASSWORD   | Eset Connect Password - required                                                                     |
| DEBUG      | Enable debug logging. Can be all non empty string. Disable by default                                |

### For executing install edr-rules-db package via pip, set all required env variables and run edr-rules-db entrypoint

### Development

App is based on poetry package manager
