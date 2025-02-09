- 9 Feb 2025

-- Goal: Experimenting `Bundler` (aka Relayer) and `Paymaster` (aka Sponsor)
--- check how evm bundler works
--- check how evm bundler handles tons of txs
--- `https://github.com/etherspot/skandha`
--- Create Bundler w Ts 
--- Bundler will receive the signed ix from user' passkey
--- Partial sign and submit to blockchain
--- evm'bundler using a eoa to sign message along with paymaster
--- build a rpc server
--- oss using fastify

--- flow should be like this:
ix has bundler's address, paymaster's address -> passkey'signature -> bundler -> bundler parse ix -> paymaster involved -> partial sign -> send to pda -> verify ops -> do the tx