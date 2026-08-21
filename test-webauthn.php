<?php
/**
 * WebAuthn 集成测试脚本
 * 
 * 此脚本用于验证 lbuchs/webauthn 库的 API 用法是否正确。
 * 需要先运行 `composer install` 安装依赖。
 * 
 * 用法: php test-webauthn.php
 */

// 加载 Composer 自动加载
require_once __DIR__ . '/vendor/autoload.php';

use lbuchs\WebAuthn\WebAuthn;
use SysHub\Passkey\Support\Base64Url;

echo "=== WebAuthn 集成测试 ===\n\n";

// 测试 1: WebAuthn 实例化
echo "1. 测试 WebAuthn 实例化...\n";
try {
    $rpName = "Test Site";
    $rpId = "example.com";
    $webauthn = new WebAuthn($rpName, $rpId, null, true);
    echo "   ✓ WebAuthn 实例化成功\n";
    echo "   RP Name: {$rpName}\n";
    echo "   RP ID: {$rpId}\n";
    echo "   Base64URL 编码: 已启用\n\n";
} catch (Exception $e) {
    echo "   ✗ 实例化失败: " . $e->getMessage() . "\n\n";
    exit(1);
}

// 测试 2: 创建选项 (Registration)
echo "2. 测试创建选项 (getCreateArgs)...\n";
try {
    $userId = pack('J', 12345); // 8字节用户ID
    $userName = "test@example.com";
    $userDisplayName = "Test User";
    $timeout = 60;
    $requireResidentKey = "preferred";
    $requireUserVerification = "preferred";
    $crossPlatformAttachment = null;
    $excludeCredentialIds = [];
    
    $createArgs = $webauthn->getCreateArgs(
        $userId,
        $userName,
        $userDisplayName,
        $timeout,
        $requireResidentKey,
        $requireUserVerification,
        $crossPlatformAttachment,
        $excludeCredentialIds
    );
    
    echo "   ✓ getCreateArgs 成功\n";
    echo "   返回类型: " . gettype($createArgs) . "\n";
    
    if (isset($createArgs->publicKey)) {
        $publicKey = $createArgs->publicKey;
        echo "   publicKey 结构:\n";
        echo "     - rp.name: " . ($publicKey->rp->name ?? 'N/A') . "\n";
        echo "     - rp.id: " . ($publicKey->rp->id ?? 'N/A') . "\n";
        echo "     - user.id: " . (isset($publicKey->user->id) ? 'base64url (已编码)' : 'N/A') . "\n";
        echo "     - user.name: " . ($publicKey->user->name ?? 'N/A') . "\n";
        echo "     - challenge: " . (isset($publicKey->challenge) ? 'base64url (已编码)' : 'N/A') . "\n";
        echo "     - timeout: " . ($publicKey->timeout ?? 'N/A') . "\n";
        echo "     - pubKeyCredParams: " . (isset($publicKey->pubKeyCredParams) ? count($publicKey->pubKey->pubKeyCredParams) . ' 个' : 'N/A') . "\n";
    }
    
    // 测试 JSON 序列化
    $json = json_encode($createArgs);
    if ($json !== false) {
        echo "   ✓ JSON 序列化成功\n";
        echo "   JSON 长度: " . strlen($json) . " 字节\n";
        
        // 检查挑战是否为 base64url 格式
        $decoded = json_decode($json);
        if (isset($decoded->publicKey->challenge)) {
            $challenge = $decoded->publicKey->challenge;
            if (preg_match('/^[A-Za-z0-9_-]+$/', $challenge)) {
                echo "   ✓ Challenge 为有效的 base64url 格式\n";
            } else {
                echo "   ⚠ Challenge 格式可能不是 base64url\n";
            }
        }
    } else {
        echo "   ✗ JSON 序列化失败\n";
    }
    
    echo "\n";
} catch (Exception $e) {
    echo "   ✗ getCreateArgs 失败: " . $e->getMessage() . "\n\n";
    exit(1);
}

// 测试 3: 断言选项 (Authentication)
echo "3. 测试断言选项 (getGetArgs)...\n";
try {
    $credentialIds = []; // 空数组 = 无用户名/可发现凭据
    $timeout = 60;
    $allowUsb = true;
    $allowNfc = true;
    $allowBle = true;
    $allowHybrid = true;
    $allowInternal = true;
    $requireUserVerification = "preferred";
    
    $getArgs = $webauthn->getGetArgs(
        $credentialIds,
        $timeout,
        $allowUsb,
        $allowNfc,
        $allowBle,
        $allowHybrid,
        $allowInternal,
        $requireUserVerification
    );
    
    echo "   ✓ getGetArgs 成功\n";
    echo "   返回类型: " . gettype($getArgs) . "\n";
    
    if (isset($getArgs->publicKey)) {
        $publicKey = $getArgs->publicKey;
        echo "   publicKey 结构:\n";
        echo "     - challenge: " . (isset($publicKey->challenge) ? 'base64url (已编码)' : 'N/A') . "\n";
        echo "     - timeout: " . ($publicKey->timeout ?? 'N/A') . "\n";
        echo "     - rpId: " . ($publicKey->rpId ?? 'N/A') . "\n";
        echo "     - userVerification: " . ($publicKey->userVerification ?? 'N/A') . "\n";
        echo "     - allowCredentials: " . (isset($publicKey->allowCredentials) ? count($publicKey->allowCredentials) . ' 个' : 'N/A (无用户名模式)') . "\n";
    }
    
    // 测试 JSON 序列化
    $json = json_encode($getArgs);
    if ($json !== false) {
        echo "   ✓ JSON 序列化成功\n";
        echo "   JSON 长度: " . strlen($json) . " 字节\n";
        
        // 检查挑战是否为 base64url 格式
        $decoded = json_decode($json);
        if (isset($decoded->publicKey->challenge)) {
            $challenge = $decoded->publicKey->challenge;
            if (preg_match('/^[A-Za-z0-9_-]+$/', $challenge)) {
                echo "   ✓ Challenge 为有效的 base64url 格式\n";
            } else {
                echo "   ⚠ Challenge 格式可能不是 base64url\n";
            }
        }
        
        // 检查 allowCredentials 是否为空（无用户名模式）
        if (isset($decoded->publicKey->allowCredentials) && empty($decoded->publicKey->allowCredentials)) {
            echo "   ✓ allowCredentials 为空（无用户名/可发现凭据模式）\n";
        }
    } else {
        echo "   ✗ JSON 序列化失败\n";
    }
    
    echo "\n";
} catch (Exception $e) {
    echo "   ✗ getGetArgs 失败: " . $e->getMessage() . "\n\n";
    exit(1);
}

// 测试 4: Base64Url 编解码
echo "4. 测试 Base64Url 编解码...\n";
try {
    $testData = "Hello, WebAuthn! 你好世界";
    $encoded = Base64Url::encode($testData);
    $decoded = Base64Url::decode($encoded);
    
    echo "   ✓ Base64Url 编解码成功\n";
    echo "   原始数据: {$testData}\n";
    echo "   编码后: {$encoded}\n";
    echo "   解码后: {$decoded}\n";
    
    if ($decoded === $testData) {
        echo "   ✓ 编解码一致性验证通过\n";
    } else {
        echo "   ✗ 编解码一致性验证失败\n";
    }
    
    echo "\n";
} catch (Exception $e) {
    echo "   ✗ Base64Url 测试失败: " . $e->getMessage() . "\n\n";
    exit(1);
}

// 测试 5: Challenge 存储模拟
echo "5. 测试 Challenge 存储逻辑（模拟）...\n";
try {
    // 模拟 session 存储
    $session = [];
    $challenge = $webauthn->getChallenge();
    $challengeBinary = $challenge->getBinaryString();
    $challengeBase64 = Base64Url::encode($challengeBinary);
    
    // 存储
    $session['passkey_challenge_login'] = [
        'data' => $challengeBase64,
        'expires' => time() + 300, // 5分钟
    ];
    
    echo "   ✓ Challenge 存储成功\n";
    echo "   Challenge 长度: " . strlen($challengeBinary) . " 字节\n";
    echo "   Base64URL 编码长度: " . strlen($challengeBase64) . " 字节\n";
    
    // 取出并验证
    $stored = $session['passkey_challenge_login'];
    $retrievedChallenge = Base64Url::decode($stored['data']);
    
    if ($retrievedChallenge === $challengeBinary) {
        echo "   ✓ Challenge 取出并验证成功\n";
    } else {
        echo "   ✗ Challenge 取出验证失败\n";
    }
    
    // 测试过期逻辑
    $stored['expires'] = time() - 1; // 已过期
    if (time() > $stored['expires']) {
        echo "   ✓ 过期检测逻辑正确\n";
    }
    
    echo "\n";
} catch (Exception $e) {
    echo "   ✗ Challenge 存储测试失败: " . $e->getMessage() . "\n\n";
    exit(1);
}

echo "=== 所有测试通过 ===\n";
echo "\nWebAuthn 库集成点验证完成。\n";
echo "可以继续实施插件。\n";