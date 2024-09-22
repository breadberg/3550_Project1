# 3550_Project1
JWKS server with RESTful API
Serve public keys and provide a unique kid and expiry to verify JWTs.
Authenticates fake users requests, issue JWTs if successful, and issue JWTs with signed expiry.
Responds with HTTP method and status codes.

To run server
unvicorn server:app --reload --port 8080
or
python -m uvicorn server:app --reload --port 8080

Use Ctrl+C to stop running
