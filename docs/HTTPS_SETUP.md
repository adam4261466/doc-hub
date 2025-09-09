# HTTPS Setup for Production with Let's Encrypt and Nginx

To ensure secure communication between your users and your server, it is critical to use HTTPS in production. This guide provides a basic example of how to set up HTTPS using Let's Encrypt and Nginx.

## Prerequisites

- A server running Linux (e.g., Ubuntu)
- Root or sudo access
- A registered domain name pointing to your server's IP
- Nginx installed on your server

## Step 1: Install Certbot

Certbot is a tool to obtain and manage Let's Encrypt SSL certificates.

```bash
sudo apt update
sudo apt install certbot python3-certbot-nginx
```

## Step 2: Obtain SSL Certificate

Run Certbot to obtain and install the certificate for your domain:

```bash
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

Follow the prompts to complete the installation.

## Step 3: Configure Nginx for HTTPS

Certbot will automatically configure Nginx to use the certificates. Ensure your Nginx server block includes:

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name yourdomain.com www.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://localhost:5000;  # Adjust to your Flask app port
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Step 4: Test HTTPS

Visit https://yourdomain.com in your browser to verify the SSL certificate is active.

## Step 5: Auto-Renewal

Let's Encrypt certificates expire every 90 days. Certbot sets up a cron job for auto-renewal. You can test it with:

```bash
sudo certbot renew --dry-run
```

---

This setup ensures all traffic is encrypted, protecting user data and authentication credentials.
