<?php
declare(strict_types=1);

namespace TwoFactorAgent;

use React\Promise\PromiseInterface;

interface DirectoryGateway
{
    /** Resolves to the adapter's result object; rejects on failure. */
    public function execute(array $request): PromiseInterface;
}
