import { API_BASE_URL } from './config.js';

// --- ฟังก์ชันสำหรับจัดการ Login Flow (ใช้ซ้ำได้) ---
async function handleSuccessfulLogin(data) {
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('user_role', data.user.role);
    localStorage.setItem('username', data.user.username);

    const welcomeMessage = `ยินดีต้อนรับคุณ ${data.user.username}`;
    
    // ปิด Swal loading (ถ้ามี) ก่อนแสดงข้อความ success
    Swal.close();

    await Swal.fire({
        icon: 'success',
        title: 'เข้าสู่ระบบสำเร็จ!',
        text: welcomeMessage,
        timer: 1500,
        showConfirmButton: false
    });
    
    redirectToDashboard(data.user.role);
}

// --- ฟังก์ชันสำหรับแสดงข้อผิดพลาด (ใช้ซ้ำได้) ---
function handleLoginError(error) {
     if (typeof Swal !== 'undefined') {
        Swal.fire({
            icon: 'error',
            title: 'เข้าสู่ระบบไม่สำเร็จ',
            text: error.message || 'กรุณาตรวจสอบข้อมูลและลองใหม่อีกครั้ง'
        });
    } else {
        alert('เข้าสู่ระบบไม่สำเร็จ: ' + error.message);
    }
}

function redirectToDashboard(role) {
    if (role === 'admin') {
        window.location.href = 'admin-dashboard.html';
    } else if (role === 'moderator') {
        window.location.href = 'moderator-dashboard.html';
    } else {
        window.location.href = 'subjects.html';
    }
}


// --- Event Listeners ---
document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    
    // 1. Listener สำหรับฟอร์ม Login ปกติ
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const username = e.target.username.value;
            const password = e.target.password.value;
            const loginButton = e.target.querySelector('button[type="submit"]');
            loginButton.disabled = true;
            loginButton.textContent = 'กำลังตรวจสอบ...';

            try {
                const response = await fetch(`${API_BASE_URL}/api/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.message || 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');
                }
                
                // ใช้ฟังก์ชันที่สร้างไว้
                await handleSuccessfulLogin(data);

            } catch (error) {
                // ใช้ฟังก์ชันที่สร้างไว้
                 handleLoginError(error);
                 loginButton.disabled = false;
                 loginButton.textContent = 'เข้าสู่ระบบ';
            }
        });
    }

    // 2. Listener สำหรับ Google Sign-In
    document.addEventListener('google-signin-success', async (event) => {
        const id_token = event.detail; // รับ id_token จาก event

        // แสดงสถานะกำลังโหลด
        Swal.fire({
            title: 'กำลังเข้าสู่ระบบผ่าน Google...',
            didOpen: () => {
                Swal.showLoading()
            },
            allowOutsideClick: false,
            allowEscapeKey: false,
        });

        try {
            // ส่ง token ไปยัง Backend ของเรา
            const response = await fetch(`${API_BASE_URL}/api/login/google`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: id_token })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || 'เกิดข้อผิดพลาดในการเข้าสู่ระบบด้วย Google');
            }

            // ถ้าสำเร็จ ให้ใช้ฟังก์ชัน handleSuccessfulLogin
            await handleSuccessfulLogin(data);

        } catch (error) {
            handleLoginError(error);
        }
    });
});