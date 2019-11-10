FROM osixia/openldap

COPY postfix-book.schema /container/service/slapd/assets/config/bootstrap/schema/postfix_book.schema
RUN rm /container/service/slapd/assets/config/bootstrap/schema/mmc/mail.schema
