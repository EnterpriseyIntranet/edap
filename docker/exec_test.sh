# This script is optimized for simplicity and speed.
# It assumes that the openldap container runs when the test script is executed.
# Then, it executes the test container, and scraps and re-creates openldap, so it is ready for the next test run.
docker-compose up python && docker-compose rm -fs openldap && docker-compose up -d openldap
