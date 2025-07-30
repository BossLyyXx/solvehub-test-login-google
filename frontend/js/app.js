import { API_BASE_URL } from './config.js';

// --- ฟังก์ชันจัดการ User Profile และ Dropdown ---
function setupUserActions() {
    const profileContainer = document.getElementById('user-profile-container');
    if (!profileContainer) return; // ถ้าไม่มีส่วนนี้ในหน้า ก็ไม่ต้องทำอะไร

    const profilePicture = document.getElementById('profile-picture');
    const usernameDisplay = document.getElementById('username-display');
    const dropdownMenu = document.getElementById('user-dropdown');
    const dropdownUsername = document.getElementById('dropdown-username');
    const dropdownRole = document.getElementById('dropdown-role');
    const adminLinkPlaceholder = document.getElementById('admin-link-placeholder');
    const logoutBtn = document.getElementById('logout-btn');

    const token = localStorage.getItem('access_token');
    const role = localStorage.getItem('user_role');
    const username = localStorage.getItem('username');
    const pictureUrl = localStorage.getItem('picture_url');

    // ถ้าไม่มี token แต่พยายามเข้าหน้าที่มี user profile ให้เด้งกลับไปหน้า login
    if (!token) {
        window.location.href = 'index.html';
        return;
    }

    // ตั้งค่าการแสดงผล
    usernameDisplay.textContent = username;
    dropdownUsername.textContent = username;
    dropdownRole.textContent = role;
    if (pictureUrl) {
        profilePicture.src = pictureUrl;
    } else {
        // รูป default กรณีไม่มีรูป (เช่น login ด้วย username/password)
        profilePicture.src = `https://ui-avatars.com/api/?name=${username}&background=0D8ABC&color=fff`;
    }

    // แสดงปุ่ม "จัดการระบบ" สำหรับ Admin/Moderator
    if (role === 'admin' || role === 'moderator') {
        const adminLink = document.createElement('a');
        adminLink.textContent = 'จัดการระบบ';
        adminLink.className = 'dropdown-item';
        adminLink.href = (role === 'admin') ? 'admin-dashboard.html' : 'moderator-dashboard.html';
        adminLinkPlaceholder.appendChild(adminLink);
    }

    // Logic การทำงานของ Dropdown
    profileContainer.addEventListener('click', (event) => {
        event.stopPropagation(); // ป้องกันการปิดเมนูทันทีเมื่อคลิกเปิด
        dropdownMenu.classList.toggle('show');
    });

    // ปิดเมนูเมื่อคลิกที่อื่น
    window.addEventListener('click', (event) => {
        if (!profileContainer.contains(event.target)) {
            dropdownMenu.classList.remove('show');
        }
    });

    // ปุ่มออกจากระบบ
    logoutBtn.addEventListener('click', (e) => {
        e.preventDefault();
        localStorage.clear();
        window.location.href = 'index.html';
    });
}

document.addEventListener('DOMContentLoaded', () => {
    const pathname = window.location.pathname.split('/').pop();

    // ตรวจสอบว่าควรจะแสดงหน้า login หรือหน้า subjects
    const token = localStorage.getItem('access_token');
    if (token && (pathname === 'index.html' || pathname === '' || pathname === '/')) {
        window.location.href = 'subjects.html';
        return;
    }
    if (!token && pathname !== 'index.html' && pathname !== '' && pathname !== '/') {
         // อนุญาตให้เข้าหน้า admin-login ได้โดยไม่ต้องมี token
        if(pathname !== 'admin-login.html') {
            window.location.href = 'index.html';
            return;
        }
    }

    // เรียกใช้ฟังก์ชันจัดการ user profile ในทุกหน้าที่ควรจะมี
    if (document.getElementById('user-profile-container')) {
        setupUserActions();
    }

    // Logic การแสดงผลตามแต่ละหน้า
    if (pathname === 'subjects.html') {
        renderSubjectsPage();
    } else if (pathname === 'solutions.html') {
        renderSolutionsPage();
    } else if (pathname === 'solution-detail.html') {
        renderSolutionDetailPage();
    }
});

async function renderSubjectsPage() {
    const grid = document.getElementById('subjects-grid');
    if (!grid) return;
    grid.innerHTML = '<p>กำลังโหลดข้อมูลวิชา...</p>';
    try {
        const response = await fetch(`${API_BASE_URL}/api/subjects`);
        if (!response.ok) throw new Error('ไม่สามารถเชื่อมต่อกับเซิร์ฟเวอร์ได้');
        const subjects = await response.json();
        grid.innerHTML = '';
        if (subjects.length === 0) {
            grid.innerHTML = '<p>ยังไม่มีข้อมูลวิชาในระบบ</p>';
            return;
        }
        subjects.forEach(subject => {
            const box = document.createElement('div');
            box.className = 'subject-box';
            box.innerHTML = `<div class="subject-icon">${subject.icon || '📚'}</div><h3>${subject.name}</h3>`;
            box.addEventListener('click', () => {
                sessionStorage.setItem('selectedSubjectName', subject.name);
                window.location.href = `solutions.html?subject_id=${subject.id}`;
            });
            grid.appendChild(box);
        });
    } catch (error) {
        grid.innerHTML = `<p style="color: red;">เกิดข้อผิดพลาด: ${error.message}</p>`;
    }
}

async function renderSolutionsPage() {
    const titleEl = document.getElementById('subject-title');
    const listEl = document.getElementById('solutions-list');
    if (!titleEl || !listEl) return;
    const urlParams = new URLSearchParams(window.location.search);
    const subjectId = urlParams.get('subject_id');
    if (!subjectId) {
        titleEl.textContent = "ไม่พบรหัสวิชา";
        return;
    }
    const subjectName = sessionStorage.getItem('selectedSubjectName');
    titleEl.textContent = `วิชา: ${subjectName || 'กำลังโหลด...'}`;
    listEl.innerHTML = '<p>กำลังโหลดรายการเฉลย...</p>';
    try {
        const response = await fetch(`${API_BASE_URL}/api/subjects/${subjectId}/solutions`);
        if (!response.ok) throw new Error('ไม่สามารถโหลดข้อมูลได้');
        const solutions = await response.json();
        listEl.innerHTML = '';
        if (solutions.length === 0) {
            listEl.innerHTML = '<p>ยังไม่มีเฉลยในวิชานี้</p>';
            return;
        }
        solutions.forEach(solution => {
            const card = document.createElement('div');
            card.className = 'solution-card';
            card.innerHTML = `
                <div class="solution-info">
                    <h4>${solution.title}</h4>
                    <p>จัดทำเมื่อ: ${solution.date}</p>
                    <p class="creator-name">เฉลยโดย: ${solution.creator_username}</p> 
                </div>
                <a href="solution-detail.html?solution_id=${solution.id}" class="btn btn-primary">ดูเฉลย</a>`;
            listEl.appendChild(card);
        });
    } catch (error) {
        listEl.innerHTML = `<p style="color: red;">เกิดข้อผิดพลาด: ${error.message}</p>`;
    }
}

async function renderSolutionDetailPage() {
    const titleEl = document.getElementById('solution-title');
    const contentEl = document.getElementById('solution-content');
    const backLink = document.getElementById('back-to-solutions');
    if (!titleEl || !contentEl) return;

    const urlParams = new URLSearchParams(window.location.search);
    const solutionId = urlParams.get('solution_id');
    if (!solutionId) { titleEl.textContent = 'ไม่พบรหัสเฉลย'; return; }
    
    titleEl.textContent = 'กำลังโหลด...';
    try {
        const response = await fetch(`${API_BASE_URL}/api/solutions/${solutionId}`);
        if (!response.ok) throw new Error('ไม่สามารถโหลดข้อมูลได้');
        const detail = await response.json();
        titleEl.textContent = detail.title;
        let finalContent = '';
        if (detail.content) {
            finalContent += `<div class="text-content">${detail.content}</div>`;
        }
        if (detail.file_path) {
            const filePath = detail.file_path;
            const fullUrl = `${API_BASE_URL}${filePath}`;
            if (/\.(jpeg|jpg|gif|png|svg)$/i.test(filePath)) {
                finalContent += `<img src="${fullUrl}" alt="Solution File" style="max-width:100%; margin-top: 1rem; border-radius: 8px;">`;
            } else {
                finalContent += `<p style="margin-top: 1rem;"><a href="${fullUrl}" target="_blank" rel="noopener noreferrer" class="btn btn-primary">ดาวน์โหลดไฟล์แนบ</a></p>`;
            }
        }
        contentEl.innerHTML = finalContent || '<p>ไม่มีเนื้อหาสำหรับเฉลยนี้</p>';
        if (backLink) {
            backLink.href = `solutions.html?subject_id=${detail.subject_id}`;
        }
    } catch (error) {
        titleEl.textContent = 'เกิดข้อผิดพลาด';
        contentEl.innerHTML = `<p style="color: red;">${error.message}</p>`;
    }
}
