// Ensure THREE is loaded
if (typeof THREE === 'undefined') {
    console.error('Three.js has not been loaded. Make sure to include it before this script.');
}

// --- Scene Setup ---
const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
const renderer = new THREE.WebGLRenderer({
    canvas: document.querySelector('#bg-canvas'),
    alpha: true // Make canvas transparent
});

renderer.setPixelRatio(window.devicePixelRatio);
renderer.setSize(window.innerWidth, window.innerHeight);
camera.position.setZ(30);

// --- Lighting ---
const pointLight = new THREE.PointLight(0xffffff, 1.5);
pointLight.position.set(5, 5, 5);
const ambientLight = new THREE.AmbientLight(0x4040ff, 0.6); // Soft blue ambient light
scene.add(pointLight, ambientLight);

// --- Object Creation Functions ---

/**
 * Creates a simple 3D book model.
 * @returns {THREE.Group} A group containing the book parts.
 */
function createBook() {
    const bookGroup = new THREE.Group();
    const coverMaterial = new THREE.MeshStandardMaterial({ color: 0x005a9c, roughness: 0.6 });
    const coverGeometry = new THREE.BoxGeometry(2.5, 3.5, 0.3);
    const cover = new THREE.Mesh(coverGeometry, coverMaterial);

    const pagesMaterial = new THREE.MeshStandardMaterial({ color: 0xf0f0f0, roughness: 0.9 });
    const pagesGeometry = new THREE.BoxGeometry(2.3, 3.3, 0.8);
    const pages = new THREE.Mesh(pagesGeometry, pagesMaterial);
    pages.position.z = 0.1;

    bookGroup.add(cover);
    bookGroup.add(pages);
    bookGroup.scale.set(0.8, 0.8, 0.8);
    return bookGroup;
}

/**
 * Creates a simple 3D laptop model.
 * @returns {THREE.Group} A group containing the laptop parts.
 */
function createLaptop() {
    const laptopGroup = new THREE.Group();
    const material = new THREE.MeshStandardMaterial({ color: 0x808080, metalness: 0.8, roughness: 0.4 });

    const screenGeometry = new THREE.BoxGeometry(4, 2.5, 0.15);
    const screen = new THREE.Mesh(screenGeometry, material);
    screen.position.y = 1.25;

    const baseGeometry = new THREE.BoxGeometry(4, 0.2, 2.5);
    const base = new THREE.Mesh(baseGeometry, material);

    laptopGroup.add(screen);
    laptopGroup.add(base);
    laptopGroup.scale.set(0.6, 0.6, 0.6);
    return laptopGroup;
}

/**
 * Creates a simple 3D pencil model.
 * @returns {THREE.Group} A group containing the pencil parts.
 */
function createPencil() {
    const pencilGroup = new THREE.Group();
    const bodyMaterial = new THREE.MeshStandardMaterial({ color: 0xffd700 });
    const bodyGeometry = new THREE.CylinderGeometry(0.2, 0.2, 3, 6);
    const body = new THREE.Mesh(bodyGeometry, bodyMaterial);

    const tipMaterial = new THREE.MeshStandardMaterial({ color: 0x2c2c2c });
    const tipGeometry = new THREE.ConeGeometry(0.2, 0.5, 6);
    const tip = new THREE.Mesh(tipGeometry, tipMaterial);
    tip.position.y = -1.75;

    pencilGroup.add(body);
    pencilGroup.add(tip);
    pencilGroup.scale.set(0.9, 0.9, 0.9);
    return pencilGroup;
}

/**
 * Creates a simple 3D lightbulb model.
 * @returns {THREE.Group} A group containing the lightbulb parts.
 */
function createLightbulb() {
    const bulbGroup = new THREE.Group();
    const glassMaterial = new THREE.MeshStandardMaterial({ color: 0xffff00, emissive: 0xffff00, emissiveIntensity: 0.3, transparent: true, opacity: 0.7 });
    const glassGeometry = new THREE.SphereGeometry(1, 32, 32);
    const glass = new THREE.Mesh(glassGeometry, glassMaterial);

    const baseMaterial = new THREE.MeshStandardMaterial({ color: 0x808080, metalness: 0.7 });
    const baseGeometry = new THREE.CylinderGeometry(0.4, 0.4, 0.6, 16);
    const base = new THREE.Mesh(baseGeometry, baseMaterial);
    base.position.y = -1;

    bulbGroup.add(glass);
    bulbGroup.add(base);
    bulbGroup.scale.set(0.7, 0.7, 0.7);
    return bulbGroup;
}

// --- Scene Population ---
const objectCreators = [createBook, createLaptop, createPencil, createLightbulb];
const objectsGroup = new THREE.Group();

for (let i = 0; i < 60; i++) { // Create 60 random objects
    const createObject = objectCreators[Math.floor(Math.random() * objectCreators.length)];
    const object = createObject();

    const [x, y, z] = Array(3).fill().map(() => THREE.MathUtils.randFloatSpread(100));
    object.position.set(x, y, z);

    object.rotation.set(Math.random() * Math.PI, Math.random() * Math.PI, Math.random() * Math.PI);

    objectsGroup.add(object);
}
scene.add(objectsGroup);

// --- Mouse Interaction ---
let mouseX = 0;
let mouseY = 0;
document.addEventListener('mousemove', (event) => {
    mouseX = (event.clientX / window.innerWidth) * 2 - 1;
    mouseY = -(event.clientY / window.innerHeight) * 2 + 1;
});

// --- Animation Loop ---
function animate() {
    requestAnimationFrame(animate);

    objectsGroup.rotation.y += 0.0005;
    objectsGroup.rotation.x += 0.0005;

    camera.position.x += (mouseX * 5 - camera.position.x) * 0.02;
    camera.position.y += (mouseY * 5 - camera.position.y) * 0.02;
    camera.lookAt(scene.position);

    pointLight.position.x = mouseX * 10;
    pointLight.position.y = mouseY * 10;
    pointLight.position.z = 15;

    renderer.render(scene, camera);
}

// --- Handle Window Resize ---
window.addEventListener('resize', () => {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
});

animate();
