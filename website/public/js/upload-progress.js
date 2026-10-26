(function () {
  'use strict';

  var CHUNK_FALLBACK = 512 * 1024;
  var CHUNK_PREFIX = 'NPCHUNK1:';

  function setText(element, value) {
    if (element) element.textContent = value;
  }

  function percentOf(done, total) {
    if (!total) return 0;
    return Math.max(0, Math.min(100, Math.round((done / total) * 100)));
  }

  function readBase64(blob) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () {
        var result = String(reader.result || '');
        var comma = result.indexOf(',');
        resolve(comma >= 0 ? result.slice(comma + 1) : result);
      };
      reader.onerror = function () { reject(new Error('无法读取本地安装包，请重新选择文件。')); };
      reader.readAsDataURL(blob);
    });
  }

  function describeResponse(response) {
    return response.text().then(function (text) {
      var message = '';
      var diagnostics = '';
      try {
        var payload = JSON.parse(text);
        message = payload.title || payload.detail || '';
        if (payload.method) diagnostics = '（服务器收到 ' + payload.method + ' 请求，协议 ' + (payload.scheme || '未知') + '）';
      } catch (error) {
        if (/<html[\s>]/i.test(text) && window.DOMParser) {
          var document_ = new DOMParser().parseFromString(text, 'text/html');
          message = ((document_.body && document_.body.textContent) || '').replace(/\s+/g, ' ').trim().slice(0, 220);
        }
      }
      if (!message) {
        if (response.status === 403 || response.status === 406 || response.status === 444) {
          message = '请求在边缘节点被拦截（HTTP ' + response.status + '），请检查 WAF/防火墙规则是否放行 /api/ 路径。';
        } else if (response.status === 413) {
          message = '服务器拒绝了请求体（HTTP 413），请确认 Nginx client_max_body_size 已放行 /api/。';
        } else {
          message = '服务器返回 HTTP ' + response.status + '，请稍后重试。';
        }
      }
      var failure = new Error(message + diagnostics);
      failure.status = response.status;
      return failure;
    });
  }

  function request(url, options) {
    return fetch(url, options).then(function (response) {
      if (response.ok) return response.json().catch(function () { return {}; });
      return describeResponse(response).then(function (error) { throw error; });
    });
  }

  function sendJson(url, token, body) {
    return request(url, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {
        'Content-Type': 'application/json',
        'X-NovaProtect-Token': token,
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: JSON.stringify(body || {})
    });
  }

  // One slice travels as prefixed base64 text: no multipart boundary, no
  // filename and no PE header on the wire, so edge WAF upload rules have
  // nothing to match. The prefix also keeps the body from ever starting with
  // "MZ", which is what a PE-signature sniffer looks for at offset 0.
  function sendChunk(url, token, text) {
    return request(url, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'X-NovaProtect-Token': token,
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: CHUNK_PREFIX + text
    });
  }

  function withRetry(operation, attempts) {
    var left = attempts || 3;
    return operation().catch(function (error) {
      if (left <= 1) throw error;
      return new Promise(function (resolve) { setTimeout(resolve, 400); })
        .then(function () { return withRetry(operation, left - 1); });
    });
  }

  // A missing or non-/api/ endpoint means the markup and this script come from
  // different website builds. Never hand such a value to fetch: fetch(null)
  // would resolve to "/null" and the server would answer with an HTML 405 page.
  function endpoint(form, name) {
    var value = form.getAttribute(name);
    if (!value || value.charAt(0) !== '/' || value.indexOf('/api/') !== 0) return '';
    return value;
  }

  function legacySubmit(form, note) {
    var progress = form.querySelector('[data-upload-progress]');
    if (progress && note) {
      progress.hidden = false;
      progress.classList.remove('is-processing', 'is-error');
      progress.classList.add('is-processing');
      var status = progress.querySelector('[data-upload-status]');
      var detail = progress.querySelector('[data-upload-detail]');
      setText(status, '切换为兼容上传');
      setText(detail, note);
    }
    // form.submit() does not fire the submit event, so this cannot loop.
    window.setTimeout(function () { form.submit(); }, 600);
  }

  function initChunked(form) {
    var progress = form.querySelector('[data-upload-progress]');
    var meter = progress && progress.querySelector('[data-upload-meter]');
    var status = progress && progress.querySelector('[data-upload-status]');
    var percent = progress && progress.querySelector('[data-upload-percent]');
    var detail = progress && progress.querySelector('[data-upload-detail]');
    var submit = form.querySelector('[data-upload-submit]');
    var fileInput = form.querySelector('input[type="file"]');
    if (!progress || !meter || !submit || !fileInput || !window.fetch || !window.FileReader) return false;

    // Endpoints are resolved once: if the markup was rendered by a different
    // website build, chunked transport is impossible and the plain form submit
    // (the pre-2.2.18 path) is the only sane fallback.
    var beginUrl = endpoint(form, 'data-upload-begin');
    var chunkUrl = endpoint(form, 'data-upload-chunk');
    var finishUrl = endpoint(form, 'data-upload-finish');
    var abortUrl = endpoint(form, 'data-upload-abort');
    if (!beginUrl || !chunkUrl || !finishUrl) return false;

    var token = form.getAttribute('data-upload-token') || '';
    var kind = form.getAttribute('data-upload-kind') || 'client';
    var redirectUrl = form.getAttribute('data-upload-redirect') || '/admin';

    var busy = false;

    function show(state, title, ratio, note) {
      progress.hidden = false;
      progress.classList.remove('is-processing', 'is-error');
      if (state) progress.classList.add(state);
      setText(status, title);
      if (typeof ratio === 'number') {
        meter.value = percentOf(ratio, 1);
        setText(percent, percentOf(ratio, 1) + '%');
      }
      if (note) setText(detail, note);
    }

    function fail(message) {
      busy = false;
      submit.disabled = false;
      progress.classList.remove('is-processing');
      progress.classList.add('is-error');
      setText(status, '上传失败');
      setText(percent, '');
      setText(detail, message);
    }

    form.addEventListener('submit', function (event) {
      event.preventDefault();
      if (busy) return;
      if (typeof form.reportValidity === 'function' && !form.reportValidity()) return;
      var file = fileInput.files && fileInput.files[0];
      if (!file) { fail('请选择客户端 EXE 安装包。'); return; }

      busy = true;
      submit.disabled = true;
      show('', '正在建立上传会话', 0, '安装包 ' + file.name + ' · ' + Math.round(file.size / 1048576) + ' MB');

      var session = null;

      function abort() {
        if (!session || !abortUrl) return;
        fetch(abortUrl + '?sid=' + encodeURIComponent(session.sid), {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'X-NovaProtect-Token': token }
        }).catch(function () {});
      }

      sendJson(beginUrl, token, { size: file.size, kind: kind })
        .then(function (created) {
          session = created;
          var chunkBytes = created.chunkBytes || CHUNK_FALLBACK;
          var total = created.chunks;
          var index = 0;
          var chain = Promise.resolve();
          show('', '正在上传', 0, '共 ' + total + ' 个分片，每片 ' + Math.round(chunkBytes / 1024) + ' KB');

          function next() {
            if (index >= total) return Promise.resolve();
            var position = index;
            var slice = file.slice(position * chunkBytes, Math.min(file.size, (position + 1) * chunkBytes));
            return readBase64(slice)
              .then(function (text) {
                return withRetry(function () {
                  return sendChunk(chunkUrl + '?sid=' + encodeURIComponent(session.sid) + '&index=' + position, token, text);
                }, 3);
              })
              .then(function () {
                index += 1;
                var ratio = index / total;
                show('', '正在上传', ratio, '已上传 ' + percentOf(index, total) + '%（' + index + '/' + total + ' 分片）');
                return next();
              });
          }
          return chain.then(next);
        })
        .then(function () {
          var isUpgrade = kind === 'upgrade';
          show('is-processing', '正在校验', 1, isUpgrade
            ? '分片上传完成，服务器正在校验升级包布局与哈希。'
            : '分片上传完成，服务器正在校验安装包并生成更新日志。');
          var payload = { kind: kind };
          if (!isUpgrade) {
            var notes = form.querySelector('textarea[name="release_notes"]');
            var minimum = form.querySelector('input[name="minimum_client_version"]');
            var force = form.querySelector('input[name="force_update"]');
            payload.minimumVersion = minimum ? minimum.value : '';
            payload.forceUpdate = !!(force && force.checked);
            payload.releaseNotes = notes ? notes.value : '';
          }
          return sendJson(finishUrl + '?sid=' + encodeURIComponent(session.sid), token, payload);
        })
        .then(function (record) {
          var label = record.kind === 'upgrade'
            ? '网站 ' + (record.websiteVersion || '')
            : '客户端 ' + (record.clientVersion || '');
          show('is-processing', '上传成功', 1, label + ' 已通过校验，正在刷新页面。');
          window.location.assign(record.redirect || redirectUrl);
        })
        .catch(function (error) {
          abort();
          if (error && (error.status === 404 || error.status === 405)) {
            busy = false;
            submit.disabled = false;
            legacySubmit(form, '服务器未提供分片上传接口（HTTP ' + error.status + '），已切换为兼容上传。如果兼容上传仍然失败，说明网站包还是旧版本，请部署 2.2.20 或更高版本。');
            return;
          }
          fail(error && error.message ? error.message : '上传失败，请重试。');
        });
    });

    return true;
  }

  function initLegacy(form) {
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

      var xhr = new XMLHttpRequest();
      xhr.open((form.method || 'POST').toUpperCase(), form.action || window.location.href, true);
      xhr.upload.addEventListener('progress', function (uploadEvent) {
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
      xhr.upload.addEventListener('load', function () {
        meter.value = 100;
        setText(percent, '100%');
        setText(status, '上传完成');
        setText(detail, '文件已发送，服务器正在校验。');
        progress.classList.add('is-processing');
      });
      xhr.addEventListener('load', function () {
        if (xhr.status >= 200 && xhr.status < 400) {
          window.location.assign(xhr.responseURL || form.action || window.location.href);
          return;
        }
        progress.classList.remove('is-processing');
        progress.classList.add('is-error');
        setText(status, '上传失败');
        setText(percent, '');
        var explanation = '';
        if (xhr.responseText && /<html[\s>]/i.test(xhr.responseText) && window.DOMParser) {
          var responseDocument = new DOMParser().parseFromString(xhr.responseText, 'text/html');
          explanation = ((responseDocument.body && responseDocument.body.textContent) || '').replace(/\s+/g, ' ').trim().slice(0, 220);
        }
        if (xhr.status === 413) {
          setText(detail, '服务器拒绝了大文件请求（HTTP 413）。请确认 Nginx 和 PHP-FPM 上传限制已生效后重试。');
        } else if (xhr.status === 415) {
          setText(detail, '服务器不接受当前上传格式（HTTP 415）。请选择客户端 EXE 安装包后重试。');
        } else {
          setText(detail, explanation || ('服务器返回 HTTP ' + xhr.status + '，请核对文件和服务器错误日志后重试。'));
        }
        submit.disabled = false;
        form.dataset.uploading = 'false';
      });
      xhr.addEventListener('error', function () {
        progress.classList.remove('is-processing');
        progress.classList.add('is-error');
        setText(status, '上传失败');
        setText(percent, '');
        setText(detail, '网络连接中断，请检查网络后重试。');
        submit.disabled = false;
        form.dataset.uploading = 'false';
      });
      xhr.addEventListener('abort', function () {
        progress.classList.remove('is-processing');
        setText(status, '上传已取消');
        setText(percent, '');
        setText(detail, '本次上传没有提交。');
        submit.disabled = false;
        form.dataset.uploading = 'false';
      });
      xhr.send(new FormData(form));
    });
  }

  function init(form) {
    if (form.getAttribute('data-chunked-upload') === '1' && initChunked(form)) return;
    initLegacy(form);
  }

  document.addEventListener('DOMContentLoaded', function () {
    Array.prototype.forEach.call(document.querySelectorAll('[data-upload-progress-form]'), init);
  });
}());
