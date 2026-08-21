(function () {
    'use strict';

    var B = window.blessing || {};

    // Base64url ↔ ArrayBuffer helpers
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

    // Recursive conversion of known fields from base64url to ArrayBuffer
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

    // API fetch wrapper
    function api(method, url, data) {
        var meta = document.querySelector('meta[name="csrf-token"]');
        var options = {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': meta ? meta.content : '',
                'Accept': 'application/json'
            },
            credentials: 'same-origin'
        };
        
        if (data) {
            options.body = JSON.stringify(data);
        }
        
        return fetch(url, options)
            .then(function (r) {
                return r.json();
            });
    }

    // Login page handler
    function handleLoginPage() {
        var btn = document.getElementById('syshub-passkey-login-btn');
        var msgEl = document.getElementById('syshub-passkey-login-message');
        
        if (!btn) return;
        
        btn.addEventListener('click', function () {
            btn.disabled = true;
            msgEl.style.display = 'none';
            
            api('GET', B.base_url + '/auth/passkey/options')
                .then(function (args) {
                    if (!args.publicKey) {
                        throw new Error(args.message || 'Failed to load WebAuthn options');
                    }
                    
                    return navigator.credentials.get(convertGetArgs(args));
                })
                .then(function (assertion) {
                    return api('POST', B.base_url + '/auth/passkey/login', {
                        id: arrayBufferToB64url(assertion.rawId),
                        clientDataJSON: arrayBufferToB64url(assertion.response.clientDataJSON),
                        authenticatorData: arrayBufferToB64url(assertion.response.authenticatorData),
                        signature: arrayBufferToB64url(assertion.response.signature),
                        userHandle: assertion.response.userHandle ? arrayBufferToB64url(assertion.response.userHandle) : null
                    });
                })
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
                    // Log error for debugging
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

    // Passkey management page handler
    function handleManagePage() {
        var configEl = document.getElementById('passkey-config');
        if (!configEl) return;
        
        var config = JSON.parse(configEl.textContent);
        var addBtn = document.getElementById('passkey-add-btn');
        var alertEl = document.getElementById('passkey-alert');
        
        function showAlert(message, type) {
            alertEl.textContent = message;
            alertEl.className = 'alert alert-' + (type || 'info');
            alertEl.style.display = 'block';
        }
        
        function hideAlert() {
            alertEl.style.display = 'none';
        }
        
        // Add passkey
        if (addBtn) {
            addBtn.addEventListener('click', function () {
                var name = prompt(config.messages.enterName);
                if (name === null) return;
                
                addBtn.disabled = true;
                showAlert(config.messages.creating, 'info');
                
                api('GET', config.createOptionsUrl)
                    .then(function (args) {
                        if (!args.publicKey) {
                            throw new Error(args.message || 'Failed to load WebAuthn options');
                        }
                        
                        return navigator.credentials.create(convertCreateArgs(args));
                    })
                    .then(function (cred) {
                        return api('POST', config.registerUrl, {
                            name: name,
                            clientDataJSON: arrayBufferToB64url(cred.response.clientDataJSON),
                            attestationObject: arrayBufferToB64url(cred.response.attestationObject)
                        });
                    })
                    .then(function (res) {
                        if (res.code === 0) {
                            window.location.reload();
                        } else {
                            throw new Error(res.message);
                        }
                    })
                    .catch(function (err) {
                        console.error('[Passkey] Create error:', err);
                        showAlert(err.message || config.messages.error, 'danger');
                    })
                    .finally(function () {
                        addBtn.disabled = false;
                    });
            });
        }
        
        // Rename passkey
        document.querySelectorAll('.passkey-rename-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var id = btn.dataset.id;
                var currentName = btn.dataset.name;
                var newName = prompt(config.messages.enterName, currentName);
                
                if (newName === null || newName === currentName) return;
                
                api('PUT', config.renameUrl + id, { name: newName })
                    .then(function (res) {
                        if (res.code === 0) {
                            window.location.reload();
                        } else {
                            throw new Error(res.message);
                        }
                    })
                    .catch(function (err) {
                        console.error('[Passkey] Rename error:', err);
                        showAlert(err.message || config.messages.error, 'danger');
                    });
            });
        });
        
        // Delete passkey
        document.querySelectorAll('.passkey-delete-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var id = btn.dataset.id;
                
                if (!confirm(config.messages.confirmDelete)) return;
                
                api('DELETE', config.deleteUrl + id)
                    .then(function (res) {
                        if (res.code === 0) {
                            window.location.reload();
                        } else {
                            throw new Error(res.message);
                        }
                    })
                    .catch(function (err) {
                        console.error('[Passkey] Delete error:', err);
                        showAlert(err.message || config.messages.error, 'danger');
                    });
            });
        });
    }

    // Initialize based on current page
    if (B.route === 'auth/login') {
        handleLoginPage();
    } else if (B.route === 'user/passkey') {
        handleManagePage();
    }
})();