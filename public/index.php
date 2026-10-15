<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/bootstrap.php';

echo PasteGuard\Web::handle($_GET, $_POST);
