// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Minimal mintable ERC20-like token used only inside this target.
/// `mint` is restricted to the single address that deployed it.
contract Token {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;

    address public immutable minter;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
        minter = msg.sender;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "not minter");
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance exceeded");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}

/// @notice Thin constant-product spot-price pool. Anyone can swap; there is
/// no fee and no external price feed, so the spot price simply reflects
/// whatever the current on-chain reserves are.
contract Pool {
    Token public col;
    Token public bor;
    uint256 public reserveCol;
    uint256 public reserveBor;

    constructor(Token _col, Token _bor) {
        col = _col;
        bor = _bor;
    }

    function sync() external {
        reserveCol = col.balanceOf(address(this));
        reserveBor = bor.balanceOf(address(this));
    }

    /// @return price of 1 COL expressed in BOR, scaled by 1e18.
    function spotPrice() external view returns (uint256) {
        require(reserveCol > 0, "no liquidity");
        return (reserveBor * 1e18) / reserveCol;
    }

    function swapColForBor(uint256 colIn) external {
        col.transferFrom(msg.sender, address(this), colIn);
        uint256 borOut = (reserveBor * colIn) / (reserveCol + colIn);
        reserveCol += colIn;
        reserveBor -= borOut;
        bor.transfer(msg.sender, borOut);
    }

    function swapBorForCol(uint256 borIn) external {
        bor.transferFrom(msg.sender, address(this), borIn);
        uint256 colOut = (reserveCol * borIn) / (reserveBor + borIn);
        reserveBor += borIn;
        reserveCol -= colOut;
        col.transfer(msg.sender, colOut);
    }
}

/// @notice Collateralized lending desk that prices collateral off the
/// `Pool`'s live spot price with no averaging, staleness check, or bound.
contract NaiveOracle {
    Token public collateralToken;
    Token public borrowToken;
    Pool public pool;

    uint256 public totalCollateral;
    uint256 public totalDebt;
    mapping(address => uint256) public collateralOf;
    mapping(address => uint256) public debtOf;

    event Deposited(address indexed who, uint256 amount);
    event Borrowed(address indexed who, uint256 amount);

    constructor() payable {
        collateralToken = new Token("Collateral", "COL");
        borrowToken = new Token("Borrow", "BOR");
        pool = new Pool(collateralToken, borrowToken);

        // Thin starting liquidity: 1 COL == 1 BOR.
        collateralToken.mint(address(pool), 100e18);
        borrowToken.mint(address(pool), 100e18);
        pool.sync();

        // Fund the lending desk so it can pay out borrows.
        borrowToken.mint(address(this), 1_000_000e18);
    }

    /// @notice Test faucet so anyone can try the protocol without an
    /// external funding source.
    function faucet() external {
        borrowToken.mint(msg.sender, 1_000e18);
    }

    function depositCollateral(uint256 amount) external {
        collateralToken.transferFrom(msg.sender, address(this), amount);
        collateralOf[msg.sender] += amount;
        totalCollateral += amount;
        emit Deposited(msg.sender, amount);
    }

    function borrow(uint256 amount) external {
        uint256 price = pool.spotPrice();
        uint256 value = (collateralOf[msg.sender] * price) / 1e18;
        require(debtOf[msg.sender] + amount <= value, "exceeds collateral value");

        debtOf[msg.sender] += amount;
        totalDebt += amount;
        borrowToken.transfer(msg.sender, amount);
        emit Borrowed(msg.sender, amount);
    }
}
