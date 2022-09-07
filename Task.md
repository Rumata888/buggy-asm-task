# Buggy asm task

We've been using this service to store our secret for a long time. Recently we had to fire one of the developers. When he left, he said that there is a critical bug in our system. After analysing his hard drive we found some strange packets (attacker_capture.pcapng). Maybe you could use them to get to the root of the issue? We've also added our interaction with the server, maybe you'll be able to decrypt the traffic.  Server and client are in their respective folders. No, the password is not actually all zeroes, don't count on it. Using the client:

```bash
docker build . -t client
docker run -it client:latest
```

Hint:

This is supposed to be a very hard task and it takes a lot of time. Unless there is some huge oversight on our part, you won't be able to solve it if you start a few hours before the end.