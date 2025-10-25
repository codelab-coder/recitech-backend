# ========== Base IA (Python) ==========
FROM python:3.11-slim AS ia
WORKDIR /app/ia
COPY ia/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ia/ .
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:app"]

# ========== Backend Node ==========
FROM node:20-slim AS backend
WORKDIR /app/backend
COPY backend/package*.json ./
RUN npm install --production
COPY backend/ .
RUN mkdir -p uploads
EXPOSE 3000
CMD ["node", "index.js"]
