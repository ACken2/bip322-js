# 使用官方的Node.js运行时作为父镜像
FROM node:14

# 在容器中设置工作目录
WORKDIR /usr/src/app

# 将 package.json 和 package-lock.json 复制到容器
COPY package*.json ./

# 安装应用程序的依赖项
RUN npm install

# 复制应用程序源代码
COPY . .

# 构建 TypeScript 项目
RUN npm run build

# 暴露应用程序运行的端口
EXPOSE 3000

# 定义运行应用程序的命令
CMD [ "node", "dist/app.js" ]
