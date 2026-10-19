(function () {
  'use strict';

  function setText(element, value) {
    if (element) element.textContent = value;
  }

  function init(form) {
    var progress = form.querySelector('[data-upload-progress]');
    var meter = progress && progress.querySelector('[data-upload-meter]');
    var status = progress && progress.querySelector('[data-upload-status]');
    var percent = progress && progress.querySelector('[data-upload-percent]');
    var detail = progress && progress.querySelector('[data-upload-detail]');
    var submit = form.querySelector('[data-upload-submit]');
    if (!progress || !meter || !submit || !window.XMLHttpRequest || !window.FormData) return;

    form.addEventListener('submit', function (event) {
      if (typeof form.reportValidity === 'function' && !form.reportValidity()) return;
      if (form.dataset.uploading === 'true') {
        event.preventDefault();
        return;
      }

      event.preventDefault();
      form.dataset.uploading = 'true';
      submit.disabled = true;
      progress.hidden = false;
      progress.classList.remove('is-processing', 'is-error');
      meter.value = 0;
      setText(status, '正在上传');
      setText(percent, '0%');

      var fileInput = form.querySelector('input[type="file"]');
      var file = fileInput && fileInput.files && fileInput.files[0];
      setText(detail, file ? '正在上传 ' + file.name : '正在上传文件...');

      var request = new XMLHttpRequest();
      request.open((form.method || 'POST').toUpperCase(), form.action || window.location.href, true);
      request.upload.addEventListener('progress', function (uploadEvent) {
        if (!uploadEvent.lengthComputable || uploadEvent.total <= 0) {
          progress.classList.add('is-processing');
          setText(status, '正在上传');
          setText(percent, '');
          return;
        }
        var value = Math.min(100, Math.round((uploadEvent.loaded / uploadEvent.total) * 100));
        meter.value = value;
        setText(percent, value + '%');
        setText(status, value >= 100 ? '上传完成' : '正在上传');
        setText(detail, value >= 100 ? '文件已发送，服务器正在校验。' : '已上传 ' + value + '%');
      });
      request.upload.addEventListener('load', function () {
        meter.value = 100;
        setText(percent, '100%');
        setText(status, '上传完成');
        setText(detail, '文件已发送，服务器正在校验。');
        progress.classList.add('is-processing');
      });
      request.addEventListener('load', function () {
        if (request.status >= 200 && request.status < 400) {
          window.location.assign(request.responseURL || form.action || window.location.href);
          return;
        }
        progress.classList.remove('is-processing');
        progress.classList.add('is-error');
        setText(status, '上传失败');
        setText(percent, '');
        var explanation = '';
        if (request.responseText && /<html[\s>]/i.test(request.responseText) && window.DOMParser) {
          var responseDocument = new DOMParser().parseFromString(request.responseText, 'text/html');
          explanation = (responseDocument.body && responseDocument.body.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 220);
        }
        if (request.status === 413) {
          setText(detail, '服务器拒绝了大文件请求（HTTP 413）。请部署最新版网站包，确认 Nginx 和 PHP-FPM 上传限制已生效后重试。');
        } else if (request.status === 415) {
          setText(detail, '服务器不接受当前上传格式（HTTP 415）。请选择客户端 EXE 安装包后重试。');
        } else {
          setText(detail, explanation || ('服务器返回 HTTP ' + request.status + '，请核对文件和服务器错误日志后重试。'));
        }
        submit.disabled = false;
        form.dataset.uploading = 'false';
      });
      request.addEventListener('error', function () {
        progress.classList.remove('is-processing');
        progress.classList.add('is-error');
        setText(status, '上传失败');
        setText(percent, '');
        setText(detail, '网络连接中断，请检查网络后重试。');
        submit.disabled = false;
        form.dataset.uploading = 'false';
      });
      request.addEventListener('abort', function () {
        progress.classList.remove('is-processing');
        setText(status, '上传已取消');
        setText(percent, '');
        setText(detail, '本次上传没有提交。');
        submit.disabled = false;
        form.dataset.uploading = 'false';
      });
      request.send(new FormData(form));
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    Array.prototype.forEach.call(document.querySelectorAll('[data-upload-progress-form]'), init);
  });
}());
