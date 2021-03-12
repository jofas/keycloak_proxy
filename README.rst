Keycloak Proxy
==============

A proxy for keycloak written in rust. Enables common API endpoints
missing from keycloak, like a registration endpoint.


Setting Up The Test Environment
-------------------------------

1. run ``docker-compose up``

2. open browser, navigate to ``http://localhost:8080``

3. click on admin console and sign in (username: ``admin``,
   pasword: ``admin``)

4. create a new realm called ``test_realm`` (add it to your
   ``KEYCLOAK_PROXY_REALM`` variable from your ``.env`` file

5. open ``test_realm->clients`` and create a new client named
   ``keycloak_proxy``, or whatever you please. You need to add it
   to your ``KEYCLOAK_PROXY_CLIENT_ID`` environment variable

6. go back to ``master->clients`` and open ``admin-cli`` client

7. set ``Access Type`` to ``confidential`` and make sure that
   ``Service Accounts Enabled`` is on

8. save client

9. navigate to ``Credentials`` tab and copy the client. Paste it into
   the ``KEYCLOAK_PROXY_ADMIN_CLI_SECRET`` variable from the ``.env``
   file

10. run ``source .env``

11. run the test suite with ``cargo test``. Alternatively you can
    test manually by running the keycloak proxy with ``cargo run``
    and ``sh debug_request.sh`` from another prompt


Enabling Permissions For The Admin Cli
--------------------------------------

Some features (like registration) rely on the proxy having access to
Keycloak's admin REST API. Besides the ``admin-cli`` setup (for
``client_id`` and ``client_secret``), you also need to enable the
right permissions:

1. start the ``keycloak_proxy`` server, e.g. via executing
   ``cargo run``

2. go to ``master->clients->admin-cli->sessions``

3. there you should see at least one session of the
   ``service-account-admin-cli`` user. Click on one of these and
   navigate to ``role mappings``

4. Add the ``admin`` role

**NOTE:** version ``v12.0.2`` has its own tab
``Service Account Roles`` where the ``admin`` role must be given
added.


TODO
----

* verbose treatment of how to properly set up the environment for
  testing

* use docker hub instead of gcr.io

* enable multiple realms

* logging

* clippy setup

* documentation

* pipeline

* codecov


Links
-----

* `<https://www.appsdeveloperblog.com/keycloak-rest-api-create-a-new-user/>`_

* `<https://stackoverflow.com/questions/65946850/keycloak-api-to-create-users-returns-a-403-forbidden>`_
