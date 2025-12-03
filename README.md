# starknet-signatures

This repository contains code to genertae keys from user signatures 

## Running the code
- typescript:

```bash
cd typescript
npm install
npm start

# OR

docker run --rm \
  -v "$(pwd)/typescript:/app" \
  -w //app \
  node:latest \
  /bin/bash -c 'npm install && npm start'
```
