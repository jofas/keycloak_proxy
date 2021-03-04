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

4. create a new realm called ``test_realm``

5. open ``test_realm->clients`` and create a new client named
   ``keycloak_proxy``

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


TODO
----

* base_url environment variables

* enable multiple realms

* logging

* clippy setup

* documentation

* pipeline

* codecov