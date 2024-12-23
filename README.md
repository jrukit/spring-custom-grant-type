How to BootRun this project 
1.) build env: docker compose up -d
2.) bootRun project
3.)test API:
curl --location 'localhost:8085/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: ••••••' \
--header 'Cookie: JSESSIONID=EBFFB10FEA3EC96EE85FC7F746002133' \
--form 'grant_type="custom"' \
--form 'username="admin"' \
--form 'password="admin"'