# Base image of python version 3.12
FROM python:3.12-slim 

# The folder inside the container where the app lives
WORKDIR /app
# install all the py libraries  
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy all the project code, like all  the files that end with .py
COPY *.py .

## expose the project in port 8000 in the api 
EXPOSE 8000

## start the api

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]