# phishlens-sandbox: headless Chromium для детонации ссылок (F-4.9.3, Business).
# Запускается без прямого выхода в интернет: production deployment должен
# подключать только разрешённый egress-прокси/сетевую policy.
FROM chromedp/headless-shell:stable
EXPOSE 9222
ENTRYPOINT ["/headless-shell/headless-shell"]
CMD ["--remote-debugging-address=0.0.0.0", "--remote-debugging-port=9222", "--disable-gpu", "--enable-unsafe-swiftshader", "--headless", "--no-first-run", "--disable-background-networking"]
