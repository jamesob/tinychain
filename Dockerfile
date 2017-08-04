FROM python:3.6.2
ADD requirements.txt ./
RUN pip install -r requirements.txt
ADD tinychain.py ./

CMD ["./tinychain.py", "serve"]
