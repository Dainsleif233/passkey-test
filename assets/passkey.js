(function () {
    'use strict';

    var B = window.blessing || {};
    var config = null;

    // ==================== Base64url Helpers ====================

    function b64urlToArrayBuffer(b64) {
        var base64 = b64.replace(/-/g, '+').replace(/_/g, '/');
        var pad = base64.length % 4;
        if (pad === 2) {
            base64 += '==';
        } else if (pad === 3) {
            base64 += '=';
        }
        
        var binary = atob(base64);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function arrayBufferToB64url(buf) {
        var bytes = new Uint8Array(buf);
        var binary = '';
        for (var i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    // ==================== WebAuthn Args Conversion ====================

    function convertCreateArgs(args) {
        if (args && args.publicKey) {
            args.publicKey.challenge = b64urlToArrayBuffer(args.publicKey.challenge);
            
            if (args.publicKey.user && args.publicKey.user.id) {
                args.publicKey.user.id = b64urlToArrayBuffer(args.publicKey.user.id);
            }
            
            if (args.publicKey.excludeCredentials) {
                args.publicKey.excludeCredentials.forEach(function (cred) {
                    cred.id = b64urlToArrayBuffer(cred.id);
                });
            }
        }
        return args;
    }

    function convertGetArgs(args) {
        if (args && args.publicKey) {
            args.publicKey.challenge = b64urlToArrayBuffer(args.publicKey.challenge);
            
            if (args.publicKey.allowCredentials) {
                args.publicKey.allowCredentials.forEach(function (cred) {
                    cred.id = b64urlToArrayBuffer(cred.id);
                });
            }
        }
        return args;
    }

    // ==================== UI Helpers ====================

    function formatDate(dateStr) {
        if (!dateStr) return config.messages.never;
        var d = new Date(dateStr);
        return d.toLocaleString();
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // ==================== CSRF Token ====================

    function getCsrfToken() {
        var meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.content : '';
    }

    // ==================== Passkey List ====================

    var passkeys = [];
    var pendingCallback = null;

    function renderPasskeyList() {
        var tbody = document.getElementById('passkey-list');
        if (!tbody) return;

        if (passkeys.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">' + 
                config.messages.empty + '</td></tr>';
            return;
        }

        var html = '';
        passkeys.forEach(function (pk) {
            html += '<tr data-id="' + pk.id + '">' +
                '<td><span class="passkey-name">' + escapeHtml(pk.name) + '</span>' +
                ' <a href="#" class="passkey-rename-btn ml-2" data-id="' + pk.id + '" data-name="' + escapeHtml(pk.name) + '" title="' + config.messages.enterName + '">' +
                '<i class="fas fa-edit"></i></a></td>' +
                '<td>' + formatDate(pk.created_at) + '</td>' +
                '<td>' + formatDate(pk.last_used_at) + '</td>' +
                '<td><button class="btn btn-danger passkey-delete-btn" data-id="' + pk.id + '">' +
                config.messages.delete +
                '</button></td>' + '</tr>';
        });
        tbody.innerHTML = html;

        // Bind events
        tbody.querySelectorAll('.passkey-rename-btn').forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                e.preventDefault();
                handleRename(parseInt(btn.dataset.id), btn.dataset.name);
            });
        });

        tbody.querySelectorAll('.passkey-delete-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                handleDeleteConfirm(parseInt(btn.dataset.id));
            });
        });
    }

    // ==================== Load Passkeys ====================

    function loadPasskeys() {
        var tbody = document.getElementById('passkey-list');
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center"><i class="fa fa-spinner fa-spin"></i></td></tr>';
        }

        fetch(config.urls.list, {
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'X-CSRF-TOKEN': getCsrfToken()
            }
        })
        .then(function (r) { return r.json(); })
        .then(function (res) {
            if (res.code === 0 && Array.isArray(res.data)) {
                passkeys = res.data;
                renderPasskeyList();
            }
        })
        .catch(function (err) {
            console.error('[Passkey] Load error:', err);
        });
    }

    // ==================== Create Passkey ====================

    function handleCreate() {
        var nameInput = document.getElementById('passkey-name-input');
        nameInput.value = '';
        
        document.getElementById('passkey-modal-title').textContent = config.messages.enterName;
        
        $('#passkey-modal').modal('show');
    }

    function doCreate() {
        var nameInput = document.getElementById('passkey-name-input');
        var name = nameInput.value.trim();
        
        $('#passkey-modal').modal('hide');
        
        if (!name) {
            return;
        }
        
        fetch(config.urls.createOptions, {
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'X-CSRF-TOKEN': getCsrfToken()
            }
        })
        .then(function (r) { return r.json(); })
        .then(function (args) {
            if (!args.publicKey) {
                throw new Error(args.message || 'Failed to load WebAuthn options');
            }
            return navigator.credentials.create(convertCreateArgs(args));
        })
        .then(function (cred) {
            return fetch(config.urls.create, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-CSRF-TOKEN': getCsrfToken()
                },
                body: JSON.stringify({
                    name: name,
                    clientDataJSON: arrayBufferToB64url(cred.response.clientDataJSON),
                    attestationObject: arrayBufferToB64url(cred.response.attestationObject)
                })
            });
        })
        .then(function (r) { return r.json(); })
        .then(function (res) {
            if (res.code === 0) {
                loadPasskeys();
            } else {
                throw new Error(res.message);
            }
        })
        .catch(function (err) {
            console.error('[Passkey] Create error:', err);
        });
    }

    // ==================== Rename Passkey ====================

    function handleRename(id, currentName) {
        var nameInput = document.getElementById('passkey-name-input');
        nameInput.value = currentName;
        
        document.getElementById('passkey-modal-title').textContent = config.messages.enterName;
        
        pendingCallback = function (newName) {
            if (newName && newName !== currentName) {
                renamePasskey(id, newName);
            }
        };
        
        $('#passkey-modal').modal('show');
    }

    function doRename() {
        var nameInput = document.getElementById('passkey-name-input');
        var newName = nameInput.value.trim();
        
        $('#passkey-modal').modal('hide');
        
        if (pendingCallback) {
            pendingCallback(newName);
            pendingCallback = null;
        }
    }

    function renamePasskey(id, newName) {
        fetch(config.urls.rename + id, {
            method: 'PUT',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-CSRF-TOKEN': getCsrfToken()
            },
            body: JSON.stringify({ name: newName })
        })
        .then(function (r) { return r.json(); })
        .then(function (res) {
            if (res.code === 0) {
                loadPasskeys();
            } else {
                throw new Error(res.message);
            }
        })
        .catch(function (err) {
            console.error('[Passkey] Rename error:', err);
        });
    }

    // ==================== Delete Passkey ====================

    function handleDeleteConfirm(id) {
        pendingCallback = function () {
            deletePasskey(id);
        };
        
        $('#passkey-delete-modal').modal('show');
    }

    function doDelete() {
        $('#passkey-delete-modal').modal('hide');
        
        if (pendingCallback) {
            pendingCallback();
            pendingCallback = null;
        }
    }

    function deletePasskey(id) {
        fetch(config.urls.delete + id, {
            method: 'DELETE',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'X-CSRF-TOKEN': getCsrfToken()
            }
        })
        .then(function (r) { return r.json(); })
        .then(function (res) {
            if (res.code === 0) {
                loadPasskeys();
            } else {
                throw new Error(res.message);
            }
        })
        .catch(function (err) {
            console.error('[Passkey] Delete error:', err);
        });
    }

    // ==================== Login Page Handler ====================

    function handleLoginPage() {
        var btn = document.getElementById('syshub-passkey-login-btn');
        var msgEl = document.getElementById('syshub-passkey-login-message');
        
        if (!btn) return;
        
        btn.addEventListener('click', function () {
            btn.disabled = true;
            msgEl.style.display = 'none';
            
            fetch(B.base_url + '/auth/passkey/options', {
                credentials: 'same-origin',
                headers: {
                    'Accept': 'application/json',
                    'X-CSRF-TOKEN': getCsrfToken()
                }
            })
            .then(function (r) { return r.json(); })
            .then(function (args) {
                if (!args.publicKey) {
                    throw new Error(args.message || 'Failed to load WebAuthn options');
                }
                return navigator.credentials.get(convertGetArgs(args));
            })
            .then(function (assertion) {
                return fetch(B.base_url + '/auth/passkey/login', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'X-CSRF-TOKEN': getCsrfToken()
                    },
                    body: JSON.stringify({
                        id: arrayBufferToB64url(assertion.rawId),
                        clientDataJSON: arrayBufferToB64url(assertion.response.clientDataJSON),
                        authenticatorData: arrayBufferToB64url(assertion.response.authenticatorData),
                        signature: arrayBufferToB64url(assertion.response.signature),
                        userHandle: assertion.response.userHandle ? arrayBufferToB64url(assertion.response.userHandle) : null
                    })
                });
            })
            .then(function (r) { return r.json(); })
            .then(function (res) {
                if (res.code === 0) {
                    window.location.href = res.data.redirectTo || B.base_url + '/user';
                } else {
                    msgEl.textContent = res.message;
                    msgEl.className = 'alert alert-danger';
                    msgEl.style.display = 'block';
                }
            })
            .catch(function (err) {
                console.error('[Passkey] Authentication error:', err);
                
                var message;
                if (err.name === 'NotAllowedError') {
                    message = btn.dataset.notAllowed || 'Authentication was not allowed';
                } else if (err.name === 'NotFoundError') {
                    message = btn.dataset.notFound || 'No passkeys found';
                } else if (err.name === 'InvalidStateError') {
                    message = btn.dataset.invalidState || 'Invalid state';
                } else {
                    message = err.message || btn.dataset.error || 'Authentication failed';
                }
                
                msgEl.textContent = message;
                msgEl.className = 'alert alert-danger';
                msgEl.style.display = 'block';
            })
            .finally(function () {
                btn.disabled = false;
            });
        });
    }

    // ==================== Manage Page Handler ====================

    function handleManagePage() {
        var configEl = document.getElementById('passkey-config');
        if (!configEl) return;
        
        config = JSON.parse(configEl.textContent);
        
        // Add button
        var addBtn = document.getElementById('passkey-add-btn');
        if (addBtn) {
            addBtn.addEventListener('click', handleCreate);
        }
        
        // Modal confirm buttons
        var modalConfirm = document.getElementById('passkey-modal-confirm');
        if (modalConfirm) {
            modalConfirm.addEventListener('click', function () {
                // Check if we're creating or renaming
                if (pendingCallback) {
                    doRename();
                } else {
                    doCreate();
                }
            });
        }
        
        var deleteConfirm = document.getElementById('passkey-delete-confirm');
        if (deleteConfirm) {
            deleteConfirm.addEventListener('click', doDelete);
        }
        
        // Load passkeys
        loadPasskeys();
    }

    // ==================== Initialize ====================

    $(document).ready(function () {
        if (B.route === 'auth/login') {
            handleLoginPage();
        } else if (B.route === 'user/passkey') {
            handleManagePage();
        }
    });
})();
