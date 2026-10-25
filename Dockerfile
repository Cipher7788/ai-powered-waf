FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN addgroup --system waf && adduser --system --ingroup waf waf
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=waf:waf . .
USER waf

EXPOSE 5000
CMD ["sh", "-c", "waitress-serve --listen=0.0.0.0:$PORT --threads=4 app:app"]
