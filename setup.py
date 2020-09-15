from setuptools import setup

setup(name="certbot_dns_conoha",
      version="0.0.2",
      description="ConoHa DNS Authenticator plugin for Certbot",
      url="https://github.com/masm11/certbot-dns-conoha",
      license="Apache-2.0",
      packages=["certbot_dns_conoha"],
      entry_points = {
          'certbot.plugins': ['dns-conoha=certbot_dns_conoha.dns_conoha:Authenticator']
      },
)
