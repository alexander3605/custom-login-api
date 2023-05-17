# custom-login-api

This project represents a backend service that exposes an API to handle users sign-up and log-in operations.

The users need to register into it providing their email,  password, some basic profile info, and then perform a safe login. In order to increase the safety of the login process, a user can enable the 2FA at the registration step to receive at the provided email a random OTP needed to complete the flow.

**Note: the OTPs are printed to the terminal on the backend service, instead of being sent by email.**

---

## Running and testing the project


### 1. (SUGGESTED) Executing the backend service from GitHub Container Registry
The quickest way to execute the project is to pull the most updated image from GHCR and spawn a container.

This can be done from any computer that has Docker installed, without even having to clone this repository locally. 
```shell
sudo docker run --rm -it  -p 8000:8000/tcp ghcr.io/alexander3605/custom-login-api:main
```
_Note: depending on your local setup, you may not need the initial `sudo` to run this command._


### _1b. (ALTERNATIVE) Execute the backend service from source code_
Alternatively, you can run the service by building the local environment necessary from the source code.
1. Install the Poetry dependency manager ([instructions here](https://python-poetry.org/docs/#installation)).
2. Clone this repository.
3. Run in the terminal `cd custom-login-api` to move to the root folder of the project.
4. Run `poetry install` from the root folder of the project to install the project dependencies.
4. Execute the service by running in the terminal the script `./scripts/dev_entrypoint.sh`

### _1c. (ALTERNATIVE) Build your own Docker image from source code and run it_
Alternatively, you can build a Docker image locally on your device and then spawn a container from that image.
1. Clone this repository.
2. Run in the terminal `cd custom-login-api` to move to the root folder of the project.
3. Build the project Docker image by running the script `./scripts/build_docker_image.sh`
4. Spawn a Docker container running the project by executing the script using  `./scripts/run_docker_container.sh`

### 2. Testing the API application.
No matter which way you picked to run the backend service, you should have the server now running in your `localhost` (a.k.a. IP address `127.0.0.1`) listening on port `8000`.

The documentation of the API is exposed by the API itself, and can be accessed at the following addresses:
- [Redoc version](http://127.0.0.1:8000/docs/redoc)
- [OpenAPI version](http://127.0.0.1:8000/docs/openapi.json)
- [Swagger version](http://127.0.0.1:8000/docs/swagger)

Now we are ready to send some HTTP requests to the service. Below are a list of requests that you can test using the `curl` UNIX tool.

- Register and login without 2FA:

```shell
# Register.
curl -X POST http://127.0.0.1:8000/register -d '{"email":"hello@gmail.com", "password": "super-safe", "surname": "bogart", "name": "john", "enable_2fa": false}'

# Login with email and password.
curl -X POST http://127.0.0.1:8000/login -d '{"email":"hello@gmail.com", "password": "super-safe"}' 

# You should receive a JWT token as response to the login request.
```

- Register and login with 2FA:
```shell
# Register.
curl -X POST http://127.0.0.1:8000/register -d '{"email":"jb@gmail.com",  "password": "penguin2", "surname": "Butler", "name": "Jamie", "enable_2fa": true}'

# Login with email and password.
curl -X POST http://127.0.0.1:8000/login -d '{"email":"jb@gmail.com", "password": "penguin2"}' 

# The response to this request should inform you that an OTP has been emailed to you. 
# However, the OTP is actually being printed to STDOUT in the backend service.
# Check the service's logs and you should find an 8-digits OTP of the shape `XXXX-XXXX`. 

# Login with email, password, and the OTP (e.g. 1234-5678).
curl -X POST http://127.0.0.1:8000/login-2fa -d '{"email":"jb@gmail.com", "password": "penguin2", "otp": "1234-5678"}' 

# You should receive a JWT token as response to the 2FA login request.
```

---


## Unit Testing 

If you have installed the poetry environment (step 1b of the section above), you can run the unit tests and check for test coverage using 
```shell
 pytest --cov=custom_login_api . 
```
At the latest commit, the test coverage is ~95%.

---

## Linting
This project uses `black`, `mypy`, `flake8` and `isort` to maintain a clean and formatted code base.

---

## Repository structure
```
- custom_login_api      --- Source code for the project.
- scripts               --- Shell scripts to easily execute various operations.
- tests                 --- Unit tests.
```
