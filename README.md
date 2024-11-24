# Flask

Flask is a lightweight WSGI web application framework. It is designed to make getting started quick and easy, with the ability to scale up to complex applications. 

# Instalation

**Requirement**
- OWASP ZAP

### First installation do:
Open a terminal in the project root directory and run

### In Windows
- *Create virtual env* ```py -m venv env```
- *Activate a virtual env:* ```.\env\Scripts\activate``` 
### In Linux
- It's required the package: ```pip install virtualenv```
- *Create virtual env* ```virtualenv env```
- *Activate a virtual env:* ```source env/bin/activate```

----
- ```pip install -r requirements.txt```   to install packages

### New packages

Remember to add new packages in the list of packges of project with the command

- ```pip freeze > requirements.txt```

To run application

```bash
$ fastapi dev main.py
  * Running on http://127.0.0.1:8000/ (Press CTRL+C to quit)
```

### Links 
- [Documentation](https://flask-restful.readthedocs.io/)
- [PyPI Releases](https://pypi.org/project/Flask/)
- [Source code](https://github.com/pallets/flask/)

----

## Install OWASP ZAP 

Required install OWASP ZAP to integration application in DAST OWAST library

Define any API_KEY_OWASP value, to use in internal communication


### Docker

Use the OWASP ZAP docker image to run system zap

```bash
docker run --network="host" -u zap -p 8080:8080 -i zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.key=<API_KEY_OWASP>
```

### File system

**Requirement**
- Java SDK 11

Downlod from [ZAP Proxy](https://www.zaproxy.org/download/), the OS system installation zap,
enter in the application and run


```bash
java -jar zap-2.15.0.jar -daemon -config api.key=<API_KEY_OWASP>
```