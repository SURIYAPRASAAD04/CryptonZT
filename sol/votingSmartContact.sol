// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title SimpleERC721
/// @notice Very small self-contained NFT contract with minting, ownership, and metadata
contract SimpleERC721 {
    string public name = "SimpleNFT";
    string public symbol = "SNFT";

    mapping(uint256 => address) private _ownerOf;
    mapping(address => uint256) private _balanceOf;
    mapping(uint256 => address) private _tokenApprovals;
    mapping(address => mapping(address => bool)) private _operatorApprovals;
    mapping(uint256 => string) private _tokenURI;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed spender, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    event Minted(address indexed to, uint256 indexed tokenId, string uri);

    uint256 private _nextTokenId = 1;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyTokenOwner(uint256 tokenId) {
        require(msg.sender == _ownerOf[tokenId], "not owner");
        _;
    }

    function balanceOf(address owner) external view returns (uint256) {
        require(owner != address(0), "zero address");
        return _balanceOf[owner];
    }

    function ownerOf(uint256 tokenId) external view returns (address) {
        return _ownerOf[tokenId];
    }

    function tokenURI(uint256 tokenId) external view returns (string memory) {
        return _tokenURI[tokenId];
    }

    function approve(address to, uint256 tokenId) external {
        address owner = _ownerOf[tokenId];
        require(msg.sender == owner || _operatorApprovals[owner][msg.sender], "not authorized");
        _tokenApprovals[tokenId] = to;
        emit Approval(owner, to, tokenId);
    }

    function setApprovalForAll(address operator, bool approved) external {
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedOrOwner(address spender, uint256 tokenId) public view returns (bool) {
        address owner = _ownerOf[tokenId];
        return (spender == owner || _tokenApprovals[tokenId] == spender || _operatorApprovals[owner][spender]);
    }

    function transferFrom(address from, address to, uint256 tokenId) public {
        require(isApprovedOrOwner(msg.sender, tokenId), "not approved");
        require(_ownerOf[tokenId] == from, "from mismatch");
        require(to != address(0), "zero dest");
        _beforeTokenTransfer(from, to, tokenId);
        // Clear approvals
        _tokenApprovals[tokenId] = address(0);
        _balanceOf[from] -= 1;
        _balanceOf[to] += 1;
        _ownerOf[tokenId] = to;
        emit Transfer(from, to, tokenId);
    }

    function safeMint(address to, string memory uri) external returns (uint256) {
        require(msg.sender == admin, "only admin");
        uint256 tokenId = _nextTokenId++;
        _ownerOf[tokenId] = to;
        _balanceOf[to] += 1;
        _tokenURI[tokenId] = uri;
        emit Minted(to, tokenId, uri);
        emit Transfer(address(0), to, tokenId);
        return tokenId;
    }

    function burn(uint256 tokenId) external onlyTokenOwner(tokenId) {
        address owner = _ownerOf[tokenId];
        _beforeTokenTransfer(owner, address(0), tokenId);
        _balanceOf[owner] -= 1;
        delete _ownerOf[tokenId];
        delete _tokenApprovals[tokenId];
        delete _tokenURI[tokenId];
        emit Transfer(owner, address(0), tokenId);
    }

    function _beforeTokenTransfer(address, address, uint256) internal virtual {
        // hook for extensions
    }

    // batch utility (basic)
    function batchMint(address to, string[] calldata uris) external returns (uint256[] memory ids) {
        require(msg.sender == admin, "only admin");
        ids = new uint256[](uris.length);
        for (uint i = 0; i < uris.length; i++) {
            ids[i] = safeMint(to, uris[i]);
        }
        return ids;
    }
}
