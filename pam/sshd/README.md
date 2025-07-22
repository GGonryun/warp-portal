### PAM Configuration and SSH Setup

I need to create a new PAM sshd module and modify PAM ssh configuration files to allow SSH access to be controlled by my custom NSS module and authentication methods.

The PAM module should be a tiny C module that sends a request to a socket server, which will return the necessary information for user authentication. This is similar to the `nss` module we already have, but it should open a new socket connection that the warp portal daemon will handle.

Enhance the primary daemon to also handle this request.

The tiny C module should be able to handle the following PAM environment variables:

```
	pamType := os.Getenv("PAM_TYPE")
	pamUser := os.Getenv("PAM_USER")
	pamRhost := os.Getenv("PAM_RHOST")
```

If a pam_type of "open_session" is detected, the module should send a request to the socket server to execute additional configuration set up tasks.

If a pam_type of "close_session" is detected, the module should send a request to the socket server to execute cleanup tasks.

We can enhance the primary daemon to also handle these requests on a new socket connection. The primary daemon should be given some placeholder logic which will simply log when a session starts or a session ends.

The makefile command should also print and tell the user that they need to add following lines into `/etc/pam.d/sshd`. It should also find and let the user know that they need to comment out any existing lines that conflict with these settings:

```
account sufficient pam_permit.so
account required pam_unix.so
session required pam_mkhomedir.so

session optional pam_exec.so seteuid <my_pam_socket_driver_path>
```
