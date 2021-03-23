FROM mongo:latest
CMD ["--port 27017"]
EXPOSE 27017

FROM python:3.9
RUN mkdir /app
WORKDIR /app
COPY requirements.txt /app
ENV IN_DOCKER_CONTAINER Yes
RUN pip3 install --no-cache-dir -r requirements.txt
COPY . /app/
CMD ["python", "app.py"]
EXPOSE 8080