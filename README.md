# custom-login-api

Your company is behind an online forum about cooking. The users need to register into it providing their email,  password, some basic profile info, and then perform a safe login. In order to increase the safety of the login process, a user can enable the 2FA at the registration step to receive at the provided email a random OTP needed to complete the flow. To reduce the complexity of the assignment (if you want) you can use as Email Sender component a fake implementation that simply logs on the stdout the OTP rather than send the email for real. 

You’re responsible to design a backend service and to actually code it in Python. You must version this project with git and provide a public URL where we can check your solution. Please don’t put any reference to our company inside the repository.

Some constraints:

- provide a README.md file with clear instructions about how we can test your service in a local development environment;

- the communication protocol will be HTTP. We expect one route to register users,  a second route to allow them to log in and a third to use in case the 2FA is enabled. You’re free to design as you like, but you’re asked to provide documentation for all of the endpoints;

- this service will operate inside a micro-services architecture and must be shipped inside a docker image, in order to be deployable in the cloud;

- we expect you to write automated tests for your project.

- Avoid using a library to generate the otp

- the session must be managed via stateless authentication with JWT

You have one week starting from today to deliver your assignment. When you’re done, please reply to this email with a working link to the project repository.

