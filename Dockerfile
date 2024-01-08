# Using the official Node.js runtime as the parent image.
FROM node:14

# Setting the working directory in the container.
WORKDIR /usr/src/app

# Copying package.json and package-lock.json into the container.
COPY package*.json ./

# Installing dependencies for the application.
RUN npm install

# Copying the source code of the application.
COPY . .

# Building TypeScript project.
RUN npm run build

# Expose the port on which the application runs.
EXPOSE 3000

# Define the command to run the application.
CMD [ "node", "dist/app.js" ]
