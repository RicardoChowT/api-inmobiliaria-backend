FROM node:20-alpine

# Crear directorio de la app
WORKDIR /app

# Copiar package.json e instalar dependencias
COPY package*.json ./
RUN npm install --only=production

# Copiar el resto del código del backend
COPY . .

# Exponer puerto
EXPOSE 3001

# Arrancar la app
CMD ["npm", "start"]