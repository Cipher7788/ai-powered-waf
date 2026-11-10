FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000

WORKDIR /app

RUN addgroup --system waf && adduser --system --ingroup waf waf
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=waf:waf . .
RUN install -d -o waf -g waf /app/logs
USER waf

EXPOSE 5000
CMD ["sh", "-c", "exec waitress-serve --listen=0.0.0.0:\"$PORT\" --threads=4 app:app"]
