<?php
session_start();

// =========================================================================
// P H P   L O G I C
// =========================================================================

// Database credentials - using environment variables for Docker
$servername = getenv('DB_HOST') ?: "db";
$username = getenv('DB_USER') ?: "root";
$password = getenv('DB_PASSWORD') ?: "example";
$dbname = getenv('DB_NAME') ?: "reportingtool";

// Table names
$users_table = 'users';
$questions_table = 'questions_section1_v20250820';
$responses_table = 'responses_section1';
$log_table = 'debug_log'; // New log table

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Function to log messages to the database
function log_message($conn, $message, $level = 'INFO') {
    global $log_table;
    $stmt = $conn->prepare("INSERT INTO `$log_table` (`message`, `level`) VALUES (?, ?)");
    if ($stmt) {
        $stmt->bind_param("ss", $message, $level);
        $stmt->execute();
        $stmt->close();
    }
}

// Function to handle a simple login and session management
function handleLogin($conn, $username, $password) {
    global $log_table;
    $stmt = $conn->prepare("SELECT id, username, password_hash, role FROM users WHERE username = ?");
    if ($stmt === false) { return ['type' => 'error', 'message' => 'Login failed. Please try again.']; }
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    $stmt->close();

    if ($user && password_verify($password, $user['password_hash'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        log_message($conn, "User '{$username}' logged in successfully with role '{$user['role']}'");
        return ['type' => 'success', 'message' => 'Login successful! Redirecting...', 'redirect' => true];
    } else {
        log_message($conn, "Failed login attempt for user '{$username}'", 'WARN');
        return ['type' => 'error', 'message' => 'Invalid username or password.'];
    }
}

// =========================================================================
// R O L E S   A N D   P E R M I S S I O N S
// =========================================================================
$is_logged_in = isset($_SESSION['user_id']);
$user_role = $is_logged_in ? $_SESSION['role'] : null;

// Permission flags for different roles
$can_submit_form = $user_role == 'officer';
$can_view_report = in_array($user_role, ['officer', 'supervisor', 'manager']);
$can_review_responses = in_array($user_role, ['supervisor', 'manager']);
$can_download_report = in_array($user_role, ['supervisor', 'manager']);
$can_manage_users = $user_role == 'manager';
$can_manage_questions = $user_role == 'manager';
$can_view_logs = $user_role == 'manager'; // New permission for viewing logs

// =========================================================================
// D A T A B A S E   S E T U P   (I N T I A L   S C H E M A)
// =========================================================================

// Create users table if it doesn't exist
$sql_users_table = "CREATE TABLE IF NOT EXISTS `$users_table` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(255) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) NOT NULL,
    `role` ENUM('officer', 'supervisor', 'manager') NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
if (!$conn->query($sql_users_table)) {
    die("Error creating table: " . $conn->error);
}

// Add a default manager user if none exist
$sql_check_user = "SELECT COUNT(*) AS count FROM `$users_table`";
$result_check_user = $conn->query($sql_check_user);
$row_check_user = $result_check_user->fetch_assoc();
if ($row_check_user['count'] == 0) {
    $password_hash = password_hash('password', PASSWORD_DEFAULT);
    $sql_insert_user = "INSERT INTO `$users_table` (`username`, `password_hash`, `role`) VALUES ('manager', ?, 'manager')";
    $stmt = $conn->prepare($sql_insert_user);
    $stmt->bind_param("s", $password_hash);
    $stmt->execute();
    $stmt->close();
    log_message($conn, "Default manager user created automatically.");
}

// Create questions table
$sql_questions_table = "CREATE TABLE IF NOT EXISTS `$questions_table` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `question_text` TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
if (!$conn->query($sql_questions_table)) {
    die("Error creating table: " . $conn->error);
}

// Add default questions if none exist
$sql_check_questions = "SELECT COUNT(*) AS count FROM `$questions_table`";
$result_check_questions = $conn->query($sql_check_questions);
$row_check_questions = $result_check_questions->fetch_assoc();
if ($row_check_questions['count'] == 0) {
    $default_questions = [
        "Are all patrol vehicles accounted for and in good working order?",
        "Have all shift reports been submitted and reviewed for accuracy?",
        "Are all critical systems (CCTV, comms) functioning correctly?",
        "Were there any notable incidents or anomalies during the shift?",
        "Confirm that all equipment and keys are properly signed in and out."
    ];
    $sql_insert_question = "INSERT INTO `$questions_table` (`question_text`) VALUES (?)";
    $stmt = $conn->prepare($sql_insert_question);
    foreach ($default_questions as $question) {
        $stmt->bind_param("s", $question);
        $stmt->execute();
    }
    $stmt->close();
    log_message($conn, "Default questions created automatically.");
}

// Create or update responses table
$sql_responses_table = "CREATE TABLE IF NOT EXISTS `$responses_table` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `question_id` INT,
    `response_status` ENUM('Noted', 'Not Noted') NOT NULL,
    `comments` TEXT,
    `user_id` INT NULL,
    `submission_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `review_status` ENUM('pending', 'approved', 'declined') DEFAULT 'pending',
    `reviewed_by_id` INT NULL,
    `review_time` TIMESTAMP NULL,
    `review_comments` TEXT NULL,
    FOREIGN KEY (`question_id`) REFERENCES `$questions_table`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`user_id`) REFERENCES `$users_table`(`id`) ON DELETE SET NULL,
    FOREIGN KEY (`reviewed_by_id`) REFERENCES `$users_table`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
$conn->query($sql_responses_table);

// Create debug_log table
$sql_log_table = "CREATE TABLE IF NOT EXISTS `$log_table` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `message` TEXT NOT NULL,
    `level` VARCHAR(50) DEFAULT 'INFO'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
$conn->query($sql_log_table);


// =========================================================================
// H A N D L E   F O R M   A C T I O N S
// =========================================================================
$message = '';
$message_type = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Handle Login
    if (isset($_POST['login_submit'])) {
        $login_result = handleLogin($conn, $_POST['username'], $_POST['password']);
        $message = $login_result['message'];
        $message_type = $login_result['type'];
        if (isset($login_result['redirect'])) {
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        }
    }

    // Handle Officer Form Submission
    if ($is_logged_in && $can_submit_form && isset($_POST['form_submit'])) {
        $all_responses_saved = true;
        $user_id = $_SESSION['user_id'];
        $sql_insert = "INSERT INTO `$responses_table` (`question_id`, `response_status`, `comments`, `user_id`) VALUES (?, ?, ?, ?)";
        $stmt = $conn->prepare($sql_insert);

        foreach ($questions as $q) {
            $question_id = $q['id'];
            $response_status = isset($_POST['response_' . $question_id]) ? $conn->real_escape_string($_POST['response_' . $question_id]) : null;
            $comments = isset($_POST['comments_' . $question_id]) ? $conn->real_escape_string($_POST['comments_' . $question_id]) : '';
            
            // Check if a response was provided for the question
            if ($response_status !== null) {
                $stmt->bind_param("issi", $question_id, $response_status, $comments, $user_id);
                if (!$stmt->execute()) {
                    $all_responses_saved = false;
                    log_message($conn, "Error saving response for question ID {$question_id}: " . $stmt->error, 'ERROR');
                    break;
                }
            }
        }
        $stmt->close();
        log_message($conn, "Officer form submitted by user ID {$user_id}. All responses saved: " . ($all_responses_saved ? 'true' : 'false'));

        $message = $all_responses_saved ? "Your responses have been saved successfully!" : "Error saving responses. Please try again.";
        $message_type = $all_responses_saved ? 'success' : 'error';
    }

    // Handle User Creation (Manager Only)
    if ($is_logged_in && $can_manage_users && isset($_POST['create_user'])) {
        $new_username = $conn->real_escape_string($_POST['new_username']);
        $new_password = password_hash($_POST['new_password'], PASSWORD_DEFAULT);
        $new_role = $conn->real_escape_string($_POST['new_role']);

        $sql_insert_user = "INSERT INTO `$users_table` (`username`, `password_hash`, `role`) VALUES (?, ?, ?)";
        $stmt = $conn->prepare($sql_insert_user);
        $stmt->bind_param("sss", $new_username, $new_password, $new_role);
        if ($stmt->execute()) {
            log_message($conn, "New user '{$new_username}' with role '{$new_role}' created by user ID {$_SESSION['user_id']}.");
            $message = "User '$new_username' created successfully!";
            $message_type = 'success';
        } else {
            log_message($conn, "Error creating user '{$new_username}': " . $stmt->error, 'ERROR');
            $message = "Error creating user: " . $stmt->error;
            $message_type = 'error';
        }
        $stmt->close();
    }

    // Handle Question Addition (Manager Only)
    if ($is_logged_in && $can_manage_questions && isset($_POST['add_question'])) {
        $new_question_text = $conn->real_escape_string($_POST['new_question_text']);

        $sql_insert_question = "INSERT INTO `$questions_table` (`question_text`) VALUES (?)";
        $stmt = $conn->prepare($sql_insert_question);
        $stmt->bind_param("s", $new_question_text);
        if ($stmt->execute()) {
            log_message($conn, "New question added by user ID {$_SESSION['user_id']}: '{$new_question_text}'");
            $message = "Question added successfully!";
            $message_type = 'success';
        } else {
            log_message($conn, "Error adding question: " . $stmt->error, 'ERROR');
            $message = "Error adding question: " . $stmt->error;
            $message_type = 'error';
        }
        $stmt->close();
    }
    
    // Handle Review Actions (Supervisor/Manager)
    if ($is_logged_in && $can_review_responses && (isset($_POST['approve_response']) || isset($_POST['decline_response']))) {
        $response_id = isset($_POST['approve_response']) ? $_POST['approve_response'] : $_POST['decline_response'];
        $new_status = isset($_POST['approve_response']) ? 'approved' : 'declined';
        $reviewer_id = $_SESSION['user_id'];
        $review_comments = isset($_POST['review_comments']) ? $conn->real_escape_string($_POST['review_comments']) : null;
        

        $sql_update_review = "UPDATE `$responses_table` SET `review_status` = ?, `reviewed_by_id` = ?, `review_time` = CURRENT_TIMESTAMP, `review_comments` = ? WHERE `id` = ?";
        $stmt = $conn->prepare($sql_update_review);
        $stmt->bind_param("sisi", $new_status, $reviewer_id, $review_comments, $response_id);
        if ($stmt->execute()) {
            log_message($conn, "Response ID {$response_id} reviewed by user ID {$reviewer_id}. Status: '{$new_status}', Comments: '{$review_comments}'");
            $message = "Response updated to '" . $new_status . "'.";
            $message_type = 'success';
        } else {
            log_message($conn, "Error updating review for response ID {$response_id}: " . $stmt->error, 'ERROR');
            $message = "Error updating response: " . $stmt->error;
            $message_type = 'error';
        }
        $stmt->close();
    }
}

// Handle Logout
if (isset($_GET['logout'])) {
    if ($is_logged_in) {
        log_message($conn, "User '{$_SESSION['username']}' logged out.");
    }
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// =========================================================================
// F E T C H   D A T A   F O R   V I E W S
// =========================================================================

// Fetch questions for the form/management
$questions = [];
$sql_questions = "SELECT id, question_text FROM `$questions_table` ORDER BY id";
$result_questions = $conn->query($sql_questions);
if ($result_questions->num_rows > 0) {
    while($row = $result_questions->fetch_assoc()) {
        $questions[] = $row;
    }
}

// Fetch all responses for the report
$responses = [];
if ($can_view_report) {
    $sql_responses = "SELECT
                        r.id,
                        q.question_text,
                        r.response_status,
                        r.comments,
                        u.username AS submitted_by,
                        r.submission_time,
                        r.review_status,
                        r.review_comments,
                        ru.username AS reviewed_by
                      FROM `$responses_table` r
                      JOIN `$questions_table` q ON r.question_id = q.id
                      LEFT JOIN `$users_table` u ON r.user_id = u.id
                      LEFT JOIN `$users_table` ru ON r.reviewed_by_id = ru.id
                      ORDER BY r.submission_time DESC";
    $result_responses = $conn->query($sql_responses);
    if ($result_responses->num_rows > 0) {
        while ($row = $result_responses->fetch_assoc()) {
            $responses[] = $row;
        }
    }
}

// Fetch users for the management view
$users = [];
if ($can_manage_users) {
    $sql_users = "SELECT id, username, role FROM `$users_table` ORDER BY role, username";
    $result_users = $conn->query($sql_users);
    if ($result_users->num_rows > 0) {
        while($row = $result_users->fetch_assoc()) {
            $users[] = $row;
        }
    }
}

// Fetch logs for the manager's debug view
$logs = [];
if ($can_view_logs) {
    $sql_logs = "SELECT timestamp, message, level FROM `$log_table` ORDER BY timestamp DESC LIMIT 200";
    $result_logs = $conn->query($sql_logs);
    if ($result_logs->num_rows > 0) {
        while ($row = $result_logs->fetch_assoc()) {
            $logs[] = $row;
        }
    }
}

// =========================================================================
// H A N D L E   J S O N   D A T A   R E Q U E S T   F O R   D O W N L O A D
// =========================================================================
if ($is_logged_in && $can_download_report && isset($_GET['download']) && $_GET['download'] == 'json') {
    header('Content-Type: application/json');
    $report_data = [];
    foreach ($responses as $response) {
        $report_data[] = [
            'question_text' => $response['question_text'],
            'response_status' => $response['response_status'],
            'comments' => $response['comments'],
            'submitted_by' => $response['submitted_by'],
            'submission_time' => $response['submission_time'],
            'review_status' => $response['review_status'],
            'reviewed_by' => $response['reviewed_by'],
            'review_comments' => $response['review_comments']
        ];
    }
    
    $full_response = [
        'report_title' => 'Daily Activity Report',
        'compiled_by' => $_SESSION['username'],
        'generation_date' => date('Y-m-d H:i:s'),
        'responses' => $report_data
    ];

    echo json_encode($full_response);
    $conn->close();
    exit;
}

$conn->close();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporting Tool - Fully Featured</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/FileSaver.js/2.0.5/FileSaver.min.js"></script>
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #f3f4f6; }
        .container { max-width: 1200px; margin: 2rem auto; padding: 2.5rem; border-radius: 1rem; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1); }
        .message-box { padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem; font-weight: 600; }
        .message-box.success { background-color: #d1fae5; color: #065f46; }
        .message-box.error { background-color: #fee2e2; color: #991b1b; }
        .report-status-pending { color: #f97316; font-weight: bold; }
        .report-status-approved { color: #10b981; font-weight: bold; }
        .report-status-declined { color: #ef4444; font-weight: bold; }
        .button { transition-transform transform hover:scale-105; }

        /* Modal styling */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.4);
            justify-content: center;
            align-items: center;
        }
        .modal-content {
            background-color: #fefefe;
            padding: 2.5rem;
            border-radius: 1rem;
            width: 90%;
            max-width: 500px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            position: relative;
        }
        .close-button {
            position: absolute;
            top: 1rem;
            right: 1.5rem;
            font-size: 2rem;
            font-weight: bold;
            color: #aaa;
            cursor: pointer;
        }
        .close-button:hover, .close-button:focus {
            color: #000;
            text-decoration: none;
            cursor: pointer;
        }
        
        @media print {
            @page { size: A4 portrait; margin: 0; }
            body { background-color: #fff; margin: 0; padding: 0; }
            .login-container, .navbar, .download-buttons, .form-container, .management-container, .action-column, .debug-section { display: none; }
            .report-container { box-shadow: none; margin: 0; padding: 1rem; max-width: 100%; }
            .report-container table { font-size: 10px; }
            .report-container table th, .report-container table td { border: 1px solid #e5e7eb; }
        }
    </style>
</head>
<body class="bg-gray-100">

    <!-- ========================================================================= -->
    <!-- S H A R E D   N A V I G A T I O N   S E C T I O N -->
    <!-- ========================================================================= -->
    <header class="bg-white shadow-md navbar">
        <div class="container mx-auto px-4 py-4 flex justify-between items-center">
            <h1 class="text-2xl font-bold text-gray-800">Reporting Tool</h1>
            <?php if ($is_logged_in): ?>
                <div class="flex items-center space-x-4">
                    <p class="text-gray-600">
                        Hello, <span class="font-semibold"><?php echo htmlspecialchars($_SESSION['username']); ?></span> (<span class="uppercase font-semibold text-blue-500"><?php echo htmlspecialchars($_SESSION['role']); ?></span>)
                    </p>
                    <a href="?logout" class="button bg-gray-200 text-gray-700 px-4 py-2 rounded-md font-semibold hover:bg-gray-300 transition">Logout</a>
                </div>
            <?php else: ?>
                <div class="text-gray-600">Please log in</div>
            <?php endif; ?>
        </div>
    </header>

    <?php if (!empty($message)): ?>
        <div class="container message-box <?php echo $message_type; ?>">
            <?php echo $message; ?>
        </div>
    <?php endif; ?>

    <?php if (!$is_logged_in): ?>
        <!-- ========================================================================= -->
        <!-- L O G I N   F O R M -->
        <!-- ========================================================================= -->
        <div class="login-container container mt-12 bg-white">
            <h2 class="text-3xl font-bold text-center text-gray-800 mb-6">Log in to continue</h2>
            <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post" class="space-y-6">
                <div>
                    <label for="username" class="block text-sm font-medium text-gray-700">Username</label>
                    <input type="text" name="username" id="username" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring focus:ring-blue-500 focus:ring-opacity-50">
                </div>
                <div>
                    <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
                    <input type="password" name="password" id="password" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring focus:ring-blue-500 focus:ring-opacity-50">
                </div>
                <button type="submit" name="login_submit" class="button w-full px-4 py-2 bg-blue-600 text-white font-semibold rounded-md shadow-md hover:bg-blue-700 transition">Log In</button>
            </form>
        </div>

    <?php else: // User is logged in, show the main content ?>
        
        <!-- ========================================================================= -->
        <!-- M A N A G E M E N T   S E C T I O N   (M A N A G E R   O N L Y) -->
        <!-- ========================================================================= -->
        <?php if ($can_manage_users || $can_manage_questions || $can_view_logs): ?>
            <div class="management-container container mt-12 bg-white">
                <h2 class="text-3xl font-bold text-gray-800 mb-6">Manager Dashboard</h2>
                
                <?php if ($can_manage_users): ?>
                    <div class="mb-8">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">User Management</h3>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                            <!-- Create New User Form -->
                            <div class="bg-gray-50 p-6 rounded-lg border border-gray-200">
                                <h4 class="text-lg font-bold mb-4">Create New User</h4>
                                <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post" class="space-y-4">
                                    <div>
                                        <label for="new_username" class="block text-sm font-medium text-gray-700">Username</label>
                                        <input type="text" name="new_username" id="new_username" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm">
                                    </div>
                                    <div>
                                        <label for="new_password" class="block text-sm font-medium text-gray-700">Password</label>
                                        <input type="password" name="new_password" id="new_password" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm">
                                    </div>
                                    <div>
                                        <label for="new_role" class="block text-sm font-medium text-gray-700">Role</label>
                                        <select name="new_role" id="new_role" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm">
                                            <option value="officer">Officer</option>
                                            <option value="supervisor">Supervisor</option>
                                            <option value="manager">Manager</option>
                                        </select>
                                    </div>
                                    <button type="submit" name="create_user" class="button px-4 py-2 bg-green-600 text-white font-semibold rounded-md shadow-md hover:bg-green-700 transition">Create User</button>
                                </form>
                            </div>

                            <!-- Existing Users List -->
                            <div class="bg-gray-50 p-6 rounded-lg border border-gray-200">
                                <h4 class="text-lg font-bold mb-4">Existing Users</h4>
                                <ul class="space-y-2">
                                    <?php foreach ($users as $u): ?>
                                        <li class="p-3 bg-white rounded-md flex justify-between items-center shadow-sm text-sm">
                                            <span><?php echo htmlspecialchars($u['username']); ?></span>
                                            <span class="px-2 py-0.5 rounded-full text-xs font-medium uppercase <?php echo ($u['role'] == 'manager') ? 'bg-blue-100 text-blue-800' : (($u['role'] == 'supervisor') ? 'bg-purple-100 text-purple-800' : 'bg-gray-100 text-gray-800'); ?>">
                                                <?php echo htmlspecialchars($u['role']); ?>
                                            </span>
                                        </li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>

                <?php if ($can_manage_questions): ?>
                    <div>
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">Report Questions Management</h3>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                            <!-- Add New Question Form -->
                            <div class="bg-gray-50 p-6 rounded-lg border border-gray-200">
                                <h4 class="text-lg font-bold mb-4">Add New Question</h4>
                                <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post" class="space-y-4">
                                    <div>
                                        <label for="new_question_text" class="block text-sm font-medium text-gray-700">Question Text</label>
                                        <textarea name="new_question_text" id="new_question_text" rows="3" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm"></textarea>
                                    </div>
                                    <button type="submit" name="add_question" class="button px-4 py-2 bg-green-600 text-white font-semibold rounded-md shadow-md hover:bg-green-700 transition">Add Question</button>
                                </form>
                            </div>

                            <!-- Existing Questions List -->
                            <div class="bg-gray-50 p-6 rounded-lg border border-gray-200">
                                <h4 class="text-lg font-bold mb-4">Existing Questions</h4>
                                <ul class="space-y-2">
                                    <?php foreach ($questions as $q): ?>
                                        <li class="p-3 bg-white rounded-md text-sm shadow-sm"><?php echo htmlspecialchars($q['question_text']); ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>

                <!-- ========================================================================= -->
                <!-- D E B U G   L O G   S E C T I O N   (M A N A G E R   O N L Y) -->
                <!-- ========================================================================= -->
                <?php if ($can_view_logs): ?>
                    <div class="mt-12 debug-section">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">Debug Log (Last 200 Entries)</h3>
                        <div class="bg-gray-50 p-6 rounded-lg border border-gray-200 overflow-y-scroll max-h-96">
                            <?php if (empty($logs)): ?>
                                <p class="text-gray-500">Log is empty.</p>
                            <?php else: ?>
                                <ul class="space-y-2">
                                    <?php foreach ($logs as $log): ?>
                                        <li class="p-2 text-xs rounded-md <?php echo ($log['level'] == 'ERROR') ? 'bg-red-100 text-red-800' : (($log['level'] == 'WARN') ? 'bg-yellow-100 text-yellow-800' : 'bg-gray-100 text-gray-800'); ?>">
                                            <span class="font-bold mr-2"><?php echo htmlspecialchars($log['timestamp']); ?></span>
                                            <span class="font-bold uppercase mr-2">[<?php echo htmlspecialchars($log['level']); ?>]</span>
                                            <span><?php echo htmlspecialchars($log['message']); ?></span>
                                        </li>
                                    <?php endforeach; ?>
                                </ul>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <!-- ========================================================================= -->
        <!-- O F F I C E R   F O R M   S E C T I O N -->
        <!-- ========================================================================= -->
        <?php if ($can_submit_form): ?>
            <div class="form-container container mt-12 bg-white">
                <h1 class="text-4xl font-bold text-center text-gray-800 mb-2">Section 1 Report</h1>
                <p class="text-center text-gray-500 mb-8">Please provide your daily report responses below.</p>
                <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
                    <?php foreach ($questions as $q): ?>
                        <div class="response-group mb-8 p-6 rounded-lg bg-gray-50 border border-gray-200">
                            <p class="text-xl text-gray-700 font-semibold mb-3"><?php echo htmlspecialchars($q['question_text']); ?></p>
                            <div class="flex items-center space-x-6 mb-4">
                                <div class="flex items-center">
                                    <input id="noted-<?php echo $q['id']; ?>" type="radio" value="Noted" name="response_<?php echo $q['id']; ?>" class="w-4 h-4 text-green-600 bg-gray-100 border-gray-300 focus:ring-green-500 rounded-full" required>
                                    <label for="noted-<?php echo $q['id']; ?>" class="ml-2 text-sm font-medium text-gray-900">Noted</label>
                                </div>
                                <div class="flex items-center">
                                    <input id="not-noted-<?php echo $q['id']; ?>" type="radio" value="Not Noted" name="response_<?php echo $q['id']; ?>" class="w-4 h-4 text-red-600 bg-gray-100 border-gray-300 focus:ring-red-500 rounded-full" required>
                                    <label for="not-noted-<?php echo $q['id']; ?>" class="ml-2 text-sm font-medium text-gray-900">Not Noted</label>
                                </div>
                            </div>
                            <label for="comments-<?php echo $q['id']; ?>" class="block text-sm font-medium text-gray-700 mb-1">Officer's Comments (Optional):</label>
                            <textarea id="comments-<?php echo $q['id']; ?>" name="comments_<?php echo $q['id']; ?>" rows="3" class="w-full p-2.5 text-sm text-gray-900 bg-white rounded-lg border border-gray-300 focus:ring-blue-500 focus:border-blue-500" placeholder="Add your comments here..."></textarea>
                        </div>
                    <?php endforeach; ?>
                    <div class="flex justify-center mt-8">
                        <button type="submit" name="form_submit" class="button w-full sm:w-auto px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg shadow-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
                            Submit Report
                        </button>
                    </div>
                </form>
            </div>
        <?php endif; ?>

        <!-- ========================================================================= -->
        <!-- R E P O R T   V I E W   S E C T I O N -->
        <!-- ========================================================================= -->
        <?php if ($can_view_report): ?>
            <div class="report-container container mt-12 bg-white">
                <h2 class="report-title text-3xl font-bold text-center text-gray-800 mb-6">Submitted Responses</h2>

                <?php if ($can_download_report): ?>
                    <div class="flex flex-col sm:flex-row justify-end space-y-2 sm:space-y-0 sm:space-x-4 mb-6 download-buttons">
                        <button onclick="downloadXLSXReport()" class="button px-4 py-2 bg-green-500 text-white font-semibold rounded-lg shadow-md hover:bg-green-600 text-center">
                            Download XLSX
                        </button>
                        <button onclick="window.print()" class="button px-4 py-2 bg-red-500 text-white font-semibold rounded-lg shadow-md hover:bg-red-600">
                            Print (PDF)
                        </button>
                    </div>
                <?php endif; ?>

                <div class="overflow-x-auto">
                    <table class="min-w-full bg-white border border-gray-200 rounded-lg">
                        <thead>
                            <tr class="bg-gray-100">
                                <th class="py-3 px-4 text-left font-semibold text-gray-600 uppercase tracking-wider">Question</th>
                                <th class="py-3 px-4 text-left font-semibold text-gray-600 uppercase tracking-wider">Status</th>
                                <th class="py-3 px-4 text-left font-semibold text-gray-600 uppercase tracking-wider">Officer's Comments</th>
                                <th class="py-3 px-4 text-left font-semibold text-gray-600 uppercase tracking-wider">Submitted By</th>
                                <th class="py-3 px-4 text-left font-semibold text-gray-600 uppercase tracking-wider">Submission Time</th>
                                <th class="py-3 px-4 text-left font-semibold text-gray-600 uppercase tracking-wider">Review Status</th>
                                <th class="py-3 px-4 text-left font-semibold text-gray-600 uppercase tracking-wider">Reviewed By</th>
                                <th class="py-3 px-4 text-left font-semibold text-gray-600 uppercase tracking-wider">Supervisor's Comments</th>
                                <?php if ($can_review_responses): ?>
                                    <th class="py-3 px-4 text-left font-semibold text-gray-600 uppercase tracking-wider action-column">Action</th>
                                <?php endif; ?>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($responses)): ?>
                                <tr><td colspan="9" class="text-center py-4 text-gray-500">No responses have been submitted yet.</td></tr>
                            <?php else: ?>
                                <?php foreach ($responses as $r): ?>
                                    <tr class="border-t border-gray-200">
                                        <td class="py-3 px-4 text-sm text-gray-800"><?php echo htmlspecialchars($r['question_text']); ?></td>
                                        <td class="py-3 px-4 text-sm font-medium <?php echo ($r['response_status'] == 'Noted') ? 'text-green-600' : 'text-red-600'; ?>"><?php echo htmlspecialchars($r['response_status']); ?></td>
                                        <td class="py-3 px-4 text-sm text-gray-600"><?php echo htmlspecialchars($r['comments']); ?></td>
                                        <td class="py-3 px-4 text-sm text-gray-600"><?php echo htmlspecialchars($r['submitted_by']); ?></td>
                                        <td class="py-3 px-4 text-sm text-gray-600"><?php echo htmlspecialchars($r['submission_time']); ?></td>
                                        <td class="py-3 px-4 text-sm <?php echo 'report-status-' . htmlspecialchars($r['review_status']); ?>"><?php echo ucfirst(htmlspecialchars($r['review_status'])); ?></td>
                                        <td class="py-3 px-4 text-sm text-gray-600"><?php echo htmlspecialchars($r['reviewed_by']); ?></td>
                                        <td class="py-3 px-4 text-sm text-gray-600"><?php echo htmlspecialchars($r['review_comments']); ?></td>
                                        
                                        <!-- ========================================================================= -->
                                        <!-- S U P E R V I S O R / M A N A G E R   A C T I O N S -->
                                        <!-- ========================================================================= -->
                                        <?php if ($can_review_responses): ?>
                                            <td class="py-3 px-4 text-sm text-gray-600 action-column">
                                                <?php if ($r['review_status'] == 'pending'): ?>
                                                    <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post" class="inline">
                                                        <input type="hidden" name="approve_response" value="<?php echo $r['id']; ?>">
                                                        <button type="submit" class="button bg-green-500 text-white px-3 py-1 rounded-full text-xs hover:bg-green-600">Approve</button>
                                                    </form>
                                                    <button type="button" onclick="openDeclineModal(<?php echo $r['id']; ?>)" class="button bg-red-500 text-white px-3 py-1 rounded-full text-xs hover:bg-red-600 ml-2">Decline</button>
                                                <?php else: ?>
                                                    <span class="text-xs text-gray-400">Reviewed</span>
                                                <?php endif; ?>
                                            </td>
                                        <?php endif; ?>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>
        
    <?php endif; ?>

    <!-- ========================================================================= -->
    <!-- C U S T O M   M O D A L   F O R   D E C L I N E -->
    <!-- ========================================================================= -->
    <div id="declineModal" class="modal">
        <div class="modal-content">
            <span class="close-button" onclick="closeDeclineModal()">&times;</span>
            <h3 class="text-2xl font-bold text-gray-800 mb-4">Add a Comment for Decline</h3>
            <p class="text-gray-600 mb-4">Please provide a reason for declining this response.</p>
            <form id="declineForm" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
                <input type="hidden" name="decline_response" id="declineResponseId">
                <textarea name="review_comments" id="reviewComments" rows="5" required class="w-full p-2.5 text-sm text-gray-900 bg-white rounded-lg border border-gray-300 focus:ring-blue-500 focus:border-blue-500" placeholder="Enter your comments here..."></textarea>
                <div class="flex justify-end mt-4">
                    <button type="submit" class="button px-4 py-2 bg-red-600 text-white font-semibold rounded-md shadow-md hover:bg-red-700 transition">Submit Decline</button>
                </div>
            </form>
        </div>
    </div>


    <script>
        // Modal functions
        function openDeclineModal(responseId) {
            document.getElementById('declineResponseId').value = responseId;
            document.getElementById('declineModal').style.display = 'flex';
        }

        function closeDeclineModal() {
            document.getElementById('declineModal').style.display = 'none';
        }

        // Close modal when clicking outside of it
        window.onclick = function(event) {
            const modal = document.getElementById('declineModal');
            if (event.target == modal) {
                closeDeclineModal();
            }
        }
        
        async function downloadXLSXReport() {
            const response = await fetch('?download=json');
            const data = await response.json();

            const reportData = [
                ["Daily Activity Report"],
                ["Compiled by:", data.compiled_by],
                ["Date:", data.generation_date],
                [],
                ["Question", "Status", "Officer's Comments", "Submitted By", "Submission Time", "Review Status", "Reviewed By", "Supervisor's Comments"],
                ...data.responses.map(res => [
                    res.question_text,
                    res.response_status,
                    res.comments,
                    res.submitted_by,
                    res.submission_time,
                    res.review_status,
                    res.reviewed_by,
                    res.review_comments
                ])
            ];

            const ws = XLSX.utils.aoa_to_sheet(reportData);
            const wb = XLSX.utils.book_new();
            XLSX.utils.book_append_sheet(wb, ws, "Report");

            const wbout = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
            saveAs(new Blob([wbout], { type: 'application/octet-stream' }), 'Daily_Activity_Report.xlsx');
        }
    </script>
</body>
</html>
