// ไฟล์นี้เป็นทางเลือกถ้าต้องการแยกการจัดการ route protection
class RouteGuard {
    constructor() {
        this.init();
    }
    
    init() {
        // ตรวจสอบเส้นทางปัจจุบัน
        const currentPath = window.location.pathname;
        const fileName = currentPath.split('/').pop();
        
        this.checkRouteAccess(fileName);
    }
    
    checkRouteAccess(fileName) {
        const protectedRoutes = {
            'admin-dashboard.html': 'admin',
            'moderator-dashboard.html': 'moderator'
        };
        
        if (protectedRoutes[fileName]) {
            const requiredRole = protectedRoutes[fileName];
            if (!this.hasAccess(requiredRole)) {
                this.redirectToUnauthorized();
            }
        }
    }
    
    hasAccess(requiredRole) {
        const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';
        const userRole = localStorage.getItem('user_role');
        
        return isLoggedIn && userRole === requiredRole;
    }
    
    redirectToUnauthorized() {
        window.location.href = '404.html';
    }
}

// เริ่มทำงานเมื่อโหลดหน้า
document.addEventListener('DOMContentLoaded', function() {
    new RouteGuard();
});
