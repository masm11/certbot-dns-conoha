# ConoHa DNS Authenticator plugin for Certbot

NOTE: This has nothing to do with one installed by `pip install certbot-dns-conoha`.

## Installation

You need Python 3.6.

```sh
python setup.py install
```

## Configuration

Create /etc/letsencrypt/conoha.ini as follows:

```ini
dns_conoha_endpoint = ...
dns_conoha_tenant_id = ...
dns_conoha_username = ...
dns_conoha_password = ...
dns_conoha_region = ...
```

- endpoint: The endpoint of ConoHa API Identity API endpoint, including `/v2.0`.
- tenant_id: You can see in your control panel.
- username: Username of ConoHa API. You can see in your control panel, after setting password of API user.
            This is neither username in your OS nor account name of contraction.
- password: Password of ConoHa API user.
- region: e.g. `tyo1`.

And do:

```sh
chmod 600 /etc/letsencrypt/conoha.ini
```

## Usage

```sh
certbot certonly --preferred-challenge dns \
                 --authenticator dns-conoha \
		 --dns-conoha-credentials /etc/letsencrypt/conoha.ini \
		 -d Your-Domain
```

If you want to get wildcard certs, you need also `--server https://acme-v02.api.letsencrypt.org/directory` for a while,
because certbot's default acme server is not changed to v2 yet.

If it succeeds, authenticator name and credentials file name are stored in `/etc/letsencrypt/renewal/Your-Domain.conf`.
So, you need not specify these information when `renew`. (But I have not test that.)

## License

Apache License 2.0.
