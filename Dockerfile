FROM python:3.8
ENV HOME /root
WORKDIR /root
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
COPY requirements.txt /root/
RUN pip install -r requirements.txt
EXPOSE 5000
COPY . /root/
CMD ["flask", "run"]