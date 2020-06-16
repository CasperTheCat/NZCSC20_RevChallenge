from ubuntu:20.04

run apt update && apt install -y python3-pip && pip3 install cryptography flask waitress

#add . .
workdir /rev/project/

env FLASK_APP=app
env FLASK_ENV=production

# Terrible
add secret.key .
add app.py .
copy templates/* templates/

EXPOSE 8080
cmd ["python3", "app.py"]

