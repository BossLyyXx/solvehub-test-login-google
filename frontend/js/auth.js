// ฟังก์ชันสำหรับจัดการล็อกอิน
function login(event) {
    event.preventDefault();
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    // ตรวจสอบข้อมูลล็อกอิน (ตัวอย่าง)
    const users = {
        'admin@example.com': { password: 'admin123', role: 'admin' },
        'moderator@example.com': { password: 'mod123', role: 'moderator' },
        'user@example.com': { password: 'user123', role: 'user' }
    };
    
    if (users[email] && users[email].password === password) {
        // เก็บข้อมูลผู้ใช้ใน localStorage
        localStorage.setItem('user_email', email);
        localStorage.setItem('user_role', users[email].role);
        localStorage.setItem('isLoggedIn', 'true');
        
        // redirect ตาม role
        redirectToDashboard(users[email].role);
    } else {
        alert('อีเมลหรือรหัสผ่านไม่ถูกต้อง');
    }
}

// แก้ไขฟังก์ชัน redirectToDashboard ให้ redirect ตาม role จริงๆ
function redirectToDashboard(role) {
    switch(role) {
        case 'admin':
            window.location.href = 'admin-dashboard.html';
            break;
        case 'moderator':
            window.location.href = 'moderator-dashboard.html';
            break;
        case 'user':
        default:
            window.location.href = 'subjects.html';
            break;
    }
}

// ฟังก์ชันตรวจสอบสิทธิ์การเข้าถึง
function checkUserRole(requiredRole) {
    const isLoggedIn = localStorage.getItem('isLoggedIn');
    const userRole = localStorage.getItem('user_role');
    
    // ถ้าไม่ได้ล็อกอิน
    if (!isLoggedIn || isLoggedIn !== 'true') {
        redirectToUnauthorized();
        return false;
    }
    
    // ถ้า role ไม่ตรงกับที่ต้องการ
    if (userRole !== requiredRole) {
        redirectToUnauthorized();
        return false;
    }
    
    return true;
}

// ฟังก์ชัน redirect ไปหน้าไม่มีสิทธิ์
function redirectToUnauthorized() {
    window.location.href = '404.html';
}

// ฟังก์ชันล็อกเอาต์
function logout() {
    localStorage.removeItem('user_email');
    localStorage.removeItem('user_role');
    localStorage.removeItem('isLoggedIn');
    window.location.href = 'index.html';
}

// ฟังก์ชันตรวจสอบว่าผู้ใช้ล็อกอินแล้วหรือไม่
function isUserLoggedIn() {
    return localStorage.getItem('isLoggedIn') === 'true';
}

// ฟังก์ชันได้ role ของผู้ใช้
function getUserRole() {
    return localStorage.getItem('user_role');
}
