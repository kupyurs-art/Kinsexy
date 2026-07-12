import time
import datetime
import asyncio
from collections import defaultdict, deque
import os
import logging
from typing import Optional, Dict, List, Set
import discord
from discord.ext import commands, tasks
import traceback
import re

# --- LOGGING SETUP (Railway Compatible) ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('KinsexyBot')

# --- HARDCODED CONFIGURATION ---
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    logger.critical("BOT_TOKEN environment variable is missing.")
    raise ValueError("BOT_TOKEN is required")

# Hardcoded configuration
LOG_CHANNEL_ID = 1508413816914837624
BYPASS_ROLE_ID = 1468249091481010197
STAFF_ROLE_ID = 1468249091481010197  # Using same role as bypass for staff

# Hardcoded whitelisted users (these users are immune to all security features)
WHITELISTED_USERS: Set[int] = {
    1394753272492851322,  # User 1
    1338442983061721201   # User 2
}

# --- RATE LIMIT CONFIGURATION ---
RATE_LIMITS = {
    'spam': {'limit': 5, 'window': 5},
    'poll': {'limit': 3, 'window': 5},
    'thread': {'limit': 3, 'window': 5},
    'kick': {'limit': 5, 'window': 5},
    'ban': {'limit': 3, 'window': 5},
    'command': {'limit': 10, 'window': 10},
    'role_delete': {'limit': 3, 'window': 5},
    'channel_delete': {'limit': 3, 'window': 5},
    'webhook_delete': {'limit': 3, 'window': 5},
    'emoji_delete': {'limit': 5, 'window': 5},
    'join_spam': {'limit': 3, 'window': 10},
}

# --- ANTI-LINK CONFIGURATION ---
ALLOWED_DOMAINS = set(os.getenv("ALLOWED_DOMAINS", "").split(',')) if os.getenv("ALLOWED_DOMAINS") else set()
BLOCKED_DOMAINS = set(os.getenv("BLOCKED_DOMAINS", "").split(',')) if os.getenv("BLOCKED_DOMAINS") else set()
ANTI_LINK_ENABLED = os.getenv("ANTI_LINK_ENABLED", "true").lower() == "true"

# --- INTENTS ---
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
intents.guilds = True
intents.moderation = True
intents.voice_states = True

bot = commands.Bot(
    command_prefix="kin.",
    intents=intents,
    help_command=None
)

# --- MEMORY STORAGE ---
kick_tracker: Dict[int, List[float]] = defaultdict(list)
ban_tracker: Dict[int, List[float]] = defaultdict(list)
spam_tracker: Dict[int, List[float]] = defaultdict(list)
poll_tracker: Dict[int, List[float]] = defaultdict(list)
thread_tracker: Dict[int, List[float]] = defaultdict(list)
command_tracker: Dict[int, List[float]] = defaultdict(list)
role_delete_tracker: Dict[int, List[float]] = defaultdict(list)
channel_delete_tracker: Dict[int, List[float]] = defaultdict(list)
webhook_delete_tracker: Dict[int, List[float]] = defaultdict(list)
emoji_delete_tracker: Dict[int, List[float]] = defaultdict(list)
join_spam_tracker: Dict[int, List[float]] = defaultdict(list)

MAX_HISTORY_SIZE = 1000
join_history = deque(maxlen=MAX_HISTORY_SIZE)
leave_history = deque(maxlen=MAX_HISTORY_SIZE)

# --- HELPERS ---

async def is_whitelisted(ctx_or_user, guild: Optional[discord.Guild] = None) -> bool:
    """Check if user is whitelisted (global whitelist or bypass role)."""
    # Handle both context and user objects
    if hasattr(ctx_or_user, 'author'):
        user = ctx_or_user.author
        if not guild:
            guild = ctx_or_user.guild
    else:
        user = ctx_or_user
    
    # Check hardcoded whitelist
    if user.id in WHITELISTED_USERS:
        return True
    
    # Check bypass role
    if guild and BYPASS_ROLE_ID != 0:
        member = guild.get_member(user.id)
        if member:
            try:
                for role in member.roles:
                    if role.id == BYPASS_ROLE_ID:
                        return True
            except Exception as e:
                logger.error(f"Error checking bypass role: {e}")
    
    return False

async def has_staff_permissions(ctx) -> bool:
    """Check if user has staff permissions (bypass role or manage_guild)."""
    if await is_whitelisted(ctx):
        return True
    
    if STAFF_ROLE_ID != 0 and ctx.guild:
        member = ctx.guild.get_member(ctx.author.id)
        if member:
            if any(role.id == STAFF_ROLE_ID for role in member.roles):
                return True
    
    # Fallback to manage_guild permission
    return ctx.author.guild_permissions.manage_guild

async def get_audit_log_actor(guild: discord.Guild, action: discord.AuditLogAction, target_id: int) -> Optional[discord.User]:
    """Safely fetch audit log actor with fallback."""
    try:
        async for entry in guild.audit_logs(limit=10, action=action):
            if entry.target.id == target_id:
                return entry.user
    except (discord.Forbidden, discord.HTTPException) as e:
        logger.warning(f"Failed to fetch audit log: {e}")
    return None

def check_rate_limit(user_id: int, tracker: dict, limit: int, window: int = 5) -> bool:
    """Check if user exceeds rate limit."""
    now = time.time()
    
    # Clean old entries
    tracker[user_id] = [t for t in tracker[user_id] if now - t <= window]
    tracker[user_id].append(now)
    
    return len(tracker[user_id]) >= limit

async def send_mod_log(
    guild: discord.Guild,
    action: str,
    actor: discord.abc.User,
    target: str,
    details: str,
    color: int = 0x2B2D31
):
    """Safely send moderation log with error handling."""
    try:
        if LOG_CHANNEL_ID == 0:
            return
            
        log_channel = guild.get_channel(LOG_CHANNEL_ID)
        if not log_channel:
            logger.warning(f"Log channel {LOG_CHANNEL_ID} not found in guild {guild.id}")
            return
        
        embed = discord.Embed(
            title=f"Security Trigger: {action}",
            description=details[:4096],
            color=color,
            timestamp=discord.utils.utcnow()
        )
        
        embed.add_field(
            name="Triggered By",
            value=f"{actor.mention}\nID: `{actor.id}`",
            inline=True
        )
        
        embed.add_field(
            name="Target",
            value=target[:1024],
            inline=True
        )
        
        current_time = int(time.time())
        embed.add_field(
            name="Time Occurred",
            value=f"<t:{current_time}:F>\n(<t:{current_time}:R>)",
            inline=False
        )
        
        embed.set_footer(text="Kinsec Security System")
        
        await log_channel.send(embed=embed)
        logger.info(f"Mod log sent: {action} by {actor.id} in {guild.id}")
        
    except discord.Forbidden:
        logger.error(f"Missing permissions to send log in guild {guild.id}")
    except discord.HTTPException as e:
        logger.error(f"Failed to send mod log: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in send_mod_log: {e}")

async def clean_trackers():
    """Periodically clean up old tracker entries to prevent memory leaks."""
    now = time.time()
    trackers = [
        kick_tracker, ban_tracker, spam_tracker, poll_tracker,
        thread_tracker, command_tracker, role_delete_tracker,
        channel_delete_tracker, webhook_delete_tracker,
        emoji_delete_tracker, join_spam_tracker
    ]
    
    for tracker in trackers:
        for user_id in list(tracker.keys()):
            tracker[user_id] = [t for t in tracker[user_id] if now - t <= 300]  # Keep last 5 minutes
            if not tracker[user_id]:
                del tracker[user_id]

def extract_links(text: str) -> List[str]:
    """Extract URLs from text."""
    url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*')
    return url_pattern.findall(text)

def is_allowed_link(url: str) -> bool:
    """Check if a URL is allowed."""
    if not ANTI_LINK_ENABLED:
        return True
    
    # If no domains configured, allow all
    if not ALLOWED_DOMAINS and not BLOCKED_DOMAINS:
        return True
    
    # Extract domain
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Check blocked domains first
        if BLOCKED_DOMAINS:
            for blocked in BLOCKED_DOMAINS:
                if blocked.lower() in domain or domain == blocked.lower():
                    return False
        
        # Check allowed domains (if configured)
        if ALLOWED_DOMAINS:
            for allowed in ALLOWED_DOMAINS:
                if allowed.lower() in domain or domain == allowed.lower():
                    return True
            return False
        
        return True
    except Exception:
        return True

# --- SECURITY DECORATORS ---

def require_whitelist():
    """Decorator to restrict commands to whitelisted users only."""
    async def predicate(ctx):
        if not await is_whitelisted(ctx):
            raise commands.MissingPermissions(["whitelist"])
        return True
    return commands.check(predicate)

def require_staff():
    """Decorator to restrict commands to staff members."""
    async def predicate(ctx):
        if not await has_staff_permissions(ctx):
            raise commands.MissingPermissions(["staff"])
        return True
    return commands.check(predicate)

def rate_limit_command(limit: int = 10, window: int = 10):
    """Rate limit for commands."""
    async def predicate(ctx):
        uid = ctx.author.id
        now = time.time()
        
        command_tracker[uid] = [t for t in command_tracker[uid] if now - t <= window]
        
        if len(command_tracker[uid]) >= limit:
            await ctx.send(f"Command rate limit exceeded. Please wait {window} seconds.")
            return False
            
        command_tracker[uid].append(now)
        return True
    return commands.check(predicate)

# --- BOT EVENTS ---

@bot.event
async def on_ready():
    """Bot startup with security checks."""
    logger.info(f"Kinsec Active. Logged in as: {bot.user} (ID: {bot.user.id})")
    logger.info(f"Whitelisted Users: {WHITELISTED_USERS}")
    logger.info(f"Bypass Role ID: {BYPASS_ROLE_ID}")
    logger.info(f"Log Channel ID: {LOG_CHANNEL_ID}")
    
    # Verify bot has necessary permissions in all guilds
    for guild in bot.guilds:
        me = guild.get_member(bot.user.id)
        if me:
            perms = me.guild_permissions
            missing = []
            if not perms.ban_members:
                missing.append("Ban Members")
            if not perms.kick_members:
                missing.append("Kick Members")
            if not perms.manage_roles:
                missing.append("Manage Roles")
            if not perms.manage_channels:
                missing.append("Manage Channels")
            if not perms.view_audit_log:
                missing.append("View Audit Log")
            if not perms.manage_messages:
                missing.append("Manage Messages")
            
            if missing:
                logger.warning(f"Missing permissions in {guild.name}: {', '.join(missing)}")
    
    if not presence_loop.is_running():
        presence_loop.start()
    
    if not cleanup_loop.is_running():
        cleanup_loop.start()

@bot.event
async def on_command_error(ctx, error):
    """Global command error handler."""
    if isinstance(error, commands.MissingPermissions):
        await ctx.send(f"You need `{', '.join(error.missing_permissions)}` permission to use this command.")
    elif isinstance(error, commands.BotMissingPermissions):
        await ctx.send(f"I need `{', '.join(error.missing_permissions)}` permission to do this.")
    elif isinstance(error, commands.CheckFailure):
        await ctx.send("You don't have permission to use this command.")
    elif isinstance(error, commands.CommandNotFound):
        pass
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"Missing required argument: `{error.param.name}`")
    elif isinstance(error, commands.BadArgument):
        await ctx.send(f"Invalid argument: {error}")
    else:
        logger.error(f"Unhandled command error: {error}\n{traceback.format_exc()}")
        await ctx.send(f"An error occurred. Please contact an administrator.")

# --- BACKGROUND TASKS ---

@tasks.loop(seconds=15)
async def presence_loop():
    """Update bot presence with error handling."""
    try:
        members = sum(g.member_count or 0 for g in bot.guilds)
        
        vc_members = sum(
            len(vc.members)
            for g in bot.guilds
            for vc in g.voice_channels
        )
        
        activities = [
            discord.Streaming(
                name="/rougekin",
                url="https://www.twitch.tv/discord"
            ),
            discord.Activity(
                type=discord.ActivityType.watching,
                name=f"{vc_members} in vc"
            ),
            discord.Activity(
                type=discord.ActivityType.watching,
                name=f"{members} members"
            ),
            discord.Activity(
                type=discord.ActivityType.competing,
                name="Security"
            )
        ]
        
        presence_loop.idx = getattr(presence_loop, "idx", 0)
        await bot.change_presence(activity=activities[presence_loop.idx % len(activities)])
        presence_loop.idx += 1
        
    except Exception as e:
        logger.error(f"Presence loop error: {e}")

@presence_loop.before_loop
async def before_presence_loop():
    await bot.wait_until_ready()

@tasks.loop(minutes=5)
async def cleanup_loop():
    """Periodically clean up old tracker data."""
    try:
        await clean_trackers()
    except Exception as e:
        logger.error(f"Cleanup loop error: {e}")

@cleanup_loop.before_loop
async def before_cleanup_loop():
    await bot.wait_until_ready()

# --- MEMBER EVENTS ---

@bot.event
async def on_member_join(member: discord.Member):
    """Track member joins with raid detection and join spam prevention."""
    try:
        join_history.append(datetime.datetime.now(datetime.timezone.utc))
        
        # Check for raid detection
        now = time.time()
        recent_joins = [t for t in join_history if now - t.timestamp() <= 60]
        if len(recent_joins) >= 10:
            logger.warning(f"Potential raid detected in {member.guild.name}: {len(recent_joins)} joins in 60s")
            
            # Send raid alert to log channel
            if LOG_CHANNEL_ID != 0:
                log_channel = member.guild.get_channel(LOG_CHANNEL_ID)
                if log_channel:
                    embed = discord.Embed(
                        title="⚠️ Potential Raid Detected",
                        description=f"**{len(recent_joins)}** members joined in the last 60 seconds.",
                        color=0xFF0000,
                        timestamp=discord.utils.utcnow()
                    )
                    embed.set_footer(text="Kinsec Security System")
                    await log_channel.send(embed=embed)
        
        # Anti-join spam: Check if this user is joining too frequently
        uid = member.id
        if check_rate_limit(uid, join_spam_tracker, RATE_LIMITS['join_spam']['limit'], RATE_LIMITS['join_spam']['window']):
            # This user is join-spamming (leaving and rejoining)
            try:
                await member.ban(
                    reason=f"Join spam detected: {RATE_LIMITS['join_spam']['limit']}+ joins in {RATE_LIMITS['join_spam']['window']}s",
                    delete_message_days=0
                )
                await send_mod_log(
                    member.guild,
                    "Join Spam Detection",
                    bot.user,
                    member.mention,
                    f"User banned for join spamming. {RATE_LIMITS['join_spam']['limit']}+ joins in {RATE_LIMITS['join_spam']['window']}s.",
                    color=0xFF0000
                )
                logger.warning(f"Join spam detected: {member} banned from {member.guild.name}")
            except discord.Forbidden:
                logger.error(f"Missing permissions to ban {member} from {member.guild.name}")
            except discord.HTTPException as e:
                logger.error(f"Failed to ban {member}: {e}")
            
    except Exception as e:
        logger.error(f"Error in on_member_join: {e}")

@bot.event
async def on_member_remove(member: discord.Member):
    """Track member leaves."""
    try:
        leave_history.append(datetime.datetime.now(datetime.timezone.utc))
    except Exception as e:
        logger.error(f"Error in on_member_remove: {e}")

# --- ANTI-LEND ADMIN EVENTS ---

@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    """Detect unauthorized admin grants."""
    try:
        before_admin = any(role.permissions.administrator for role in before.roles)
        after_admin = any(role.permissions.administrator for role in after.roles)
        
        if before_admin or not after_admin:
            return
        
        guild = after.guild
        actor = await get_audit_log_actor(guild, discord.AuditLogAction.member_role_update, after.id)
        
        if not actor or actor.id == bot.user.id or await is_whitelisted(actor, guild):
            return
        
        admin_roles_added = [
            role for role in after.roles 
            if role.permissions.administrator and role not in before.roles
        ]
        
        if admin_roles_added:
            await after.remove_roles(*admin_roles_added, reason="Security: Anti-Lend Admin")
            
            try:
                await guild.ban(
                    actor, 
                    reason="Security: Anti-Lend Admin (Unauthorized Admin Assignment)",
                    delete_message_days=1
                )
            except discord.Forbidden:
                logger.error(f"Missing permissions to ban {actor} from {guild.name}")
            
            await send_mod_log(
                guild,
                "Anti-Lend Admin (Role Assigned)",
                actor,
                after.mention,
                f"User attempted to assign admin role(s): {', '.join(r.name for r in admin_roles_added)}",
                color=0xFF0000
            )
            
            logger.warning(f"Anti-Lend Admin triggered: {actor} banned from {guild.name}")
            
    except discord.Forbidden:
        logger.error(f"Missing permissions in {guild.name if 'guild' in locals() else 'unknown'} for on_member_update")
    except Exception as e:
        logger.error(f"Error in on_member_update: {e}")

@bot.event
async def on_guild_role_update(before: discord.Role, after: discord.Role):
    """Detect unauthorized admin role edits."""
    try:
        if before.permissions.administrator or not after.permissions.administrator:
            return
            
        guild = after.guild
        actor = await get_audit_log_actor(guild, discord.AuditLogAction.role_update, after.id)
        
        if not actor or actor.id == bot.user.id or await is_whitelisted(actor, guild):
            return
        
        await after.edit(
            permissions=before.permissions,
            reason="Security: Anti-Lend Admin Revert"
        )
        
        try:
            await guild.ban(
                actor,
                reason="Security: Anti-Lend Admin (Unauthorized Role Edit)",
                delete_message_days=1
            )
        except discord.Forbidden:
            logger.error(f"Missing permissions to ban {actor} from {guild.name}")
        
        await send_mod_log(
            guild,
            "Anti-Lend Admin (Role Edit)",
            actor,
            f"Role: {after.name}",
            f"User attempted to add Administrator to role {after.name}",
            color=0xFF0000
        )
        
        logger.warning(f"Anti-Lend Admin role edit triggered: {actor} banned from {guild.name}")
        
    except discord.Forbidden:
        logger.error(f"Missing permissions in {guild.name if 'guild' in locals() else 'unknown'} for on_guild_role_update")
    except Exception as e:
        logger.error(f"Error in on_guild_role_update: {e}")

# --- AUDIT LOG EVENTS ---

@bot.event
async def on_audit_log_entry_create(entry: discord.AuditLogEntry):
    """Monitor audit logs for malicious activity with threshold-based banning."""
    try:
        guild = entry.guild
        actor = entry.user
        
        if not actor or actor.id == bot.user.id or await is_whitelisted(actor, guild):
            return
        
        # MASS KICK DETECTION
        if entry.action == discord.AuditLogAction.kick:
            if check_rate_limit(actor.id, kick_tracker, RATE_LIMITS['kick']['limit'], RATE_LIMITS['kick']['window']):
                try:
                    await guild.ban(
                        actor,
                        reason=f"Security: Mass Kick Detection ({RATE_LIMITS['kick']['limit']}+ kicks in {RATE_LIMITS['kick']['window']}s)",
                        delete_message_days=1
                    )
                except discord.Forbidden:
                    logger.error(f"Missing permissions to ban {actor} from {guild.name}")
                
                await send_mod_log(
                    guild,
                    "Mass Kick Detected",
                    actor,
                    "Multiple Members",
                    f"User banned for mass kicking. {RATE_LIMITS['kick']['limit']}+ kicks in {RATE_LIMITS['kick']['window']}s.",
                    color=0xFF0000
                )
                logger.warning(f"Mass kick detected: {actor} banned from {guild.name}")
        
        # MASS BAN DETECTION
        elif entry.action == discord.AuditLogAction.ban:
            if check_rate_limit(actor.id, ban_tracker, RATE_LIMITS['ban']['limit'], RATE_LIMITS['ban']['window']):
                try:
                    await guild.ban(
                        actor,
                        reason=f"Security: Mass Ban Detection ({RATE_LIMITS['ban']['limit']}+ bans in {RATE_LIMITS['ban']['window']}s)",
                        delete_message_days=1
                    )
                except discord.Forbidden:
                    logger.error(f"Missing permissions to ban {actor} from {guild.name}")
                
                await send_mod_log(
                    guild,
                    "Mass Ban Detected",
                    actor,
                    "Multiple Members",
                    f"User banned for mass banning. {RATE_LIMITS['ban']['limit']}+ bans in {RATE_LIMITS['ban']['window']}s.",
                    color=0xFF0000
                )
                logger.warning(f"Mass ban detected: {actor} banned from {guild.name}")
        
        # ROLE DELETE DETECTION
        elif entry.action == discord.AuditLogAction.role_delete:
            if check_rate_limit(actor.id, role_delete_tracker, RATE_LIMITS['role_delete']['limit'], RATE_LIMITS['role_delete']['window']):
                role_delete_tracker[actor.id].clear()
                
                try:
                    await guild.ban(
                        actor,
                        reason=f"Anti-Nuke: Mass Role Deletion ({RATE_LIMITS['role_delete']['limit']}+ roles in {RATE_LIMITS['role_delete']['window']}s)",
                        delete_message_days=1
                    )
                except discord.Forbidden:
                    logger.error(f"Missing permissions to ban {actor} from {guild.name}")
                except discord.HTTPException as e:
                    logger.error(f"Failed to ban {actor}: {e}")
                
                await send_mod_log(
                    guild,
                    "Anti-Nuke: Mass Role Deletion",
                    actor,
                    f"Role: {entry.target.name if entry.target else 'Unknown'}",
                    f"User banned for deleting {RATE_LIMITS['role_delete']['limit']}+ roles in {RATE_LIMITS['role_delete']['window']} seconds.",
                    color=0xFF0000
                )
                logger.warning(f"Mass role deletion detected: {actor} banned from {guild.name}")
            else:
                await send_mod_log(
                    guild,
                    "Role Deletion",
                    actor,
                    f"Role: {entry.target.name if entry.target else 'Unknown'}",
                    f"User deleted a role. ({len(role_delete_tracker[actor.id])}/{RATE_LIMITS['role_delete']['limit']} in {RATE_LIMITS['role_delete']['window']}s)",
                    color=0xFFA500
                )
        
        # CHANNEL DELETE DETECTION
        elif entry.action == discord.AuditLogAction.channel_delete:
            if check_rate_limit(actor.id, channel_delete_tracker, RATE_LIMITS['channel_delete']['limit'], RATE_LIMITS['channel_delete']['window']):
                channel_delete_tracker[actor.id].clear()
                
                try:
                    await guild.ban(
                        actor,
                        reason=f"Anti-Nuke: Mass Channel Deletion ({RATE_LIMITS['channel_delete']['limit']}+ channels in {RATE_LIMITS['channel_delete']['window']}s)",
                        delete_message_days=1
                    )
                except discord.Forbidden:
                    logger.error(f"Missing permissions to ban {actor} from {guild.name}")
                except discord.HTTPException as e:
                    logger.error(f"Failed to ban {actor}: {e}")
                
                await send_mod_log(
                    guild,
                    "Anti-Nuke: Mass Channel Deletion",
                    actor,
                    f"Channel: {entry.target.name if entry.target else 'Unknown'}",
                    f"User banned for deleting {RATE_LIMITS['channel_delete']['limit']}+ channels in {RATE_LIMITS['channel_delete']['window']} seconds.",
                    color=0xFF0000
                )
                logger.warning(f"Mass channel deletion detected: {actor} banned from {guild.name}")
            else:
                await send_mod_log(
                    guild,
                    "Channel Deletion",
                    actor,
                    f"Channel: {entry.target.name if entry.target else 'Unknown'}",
                    f"User deleted a channel. ({len(channel_delete_tracker[actor.id])}/{RATE_LIMITS['channel_delete']['limit']} in {RATE_LIMITS['channel_delete']['window']}s)",
                    color=0xFFA500
                )
        
        # WEBHOOK DELETE DETECTION
        elif entry.action == discord.AuditLogAction.webhook_delete:
            if check_rate_limit(actor.id, webhook_delete_tracker, RATE_LIMITS['webhook_delete']['limit'], RATE_LIMITS['webhook_delete']['window']):
                webhook_delete_tracker[actor.id].clear()
                
                try:
                    await guild.ban(
                        actor,
                        reason=f"Anti-Nuke: Mass Webhook Deletion ({RATE_LIMITS['webhook_delete']['limit']}+ webhooks in {RATE_LIMITS['webhook_delete']['window']}s)",
                        delete_message_days=1
                    )
                except discord.Forbidden:
                    logger.error(f"Missing permissions to ban {actor} from {guild.name}")
                except discord.HTTPException as e:
                    logger.error(f"Failed to ban {actor}: {e}")
                
                await send_mod_log(
                    guild,
                    "Anti-Nuke: Mass Webhook Deletion",
                    actor,
                    f"Webhook: {entry.target.name if entry.target else 'Unknown'}",
                    f"User banned for deleting {RATE_LIMITS['webhook_delete']['limit']}+ webhooks in {RATE_LIMITS['webhook_delete']['window']} seconds.",
                    color=0xFF0000
                )
                logger.warning(f"Mass webhook deletion detected: {actor} banned from {guild.name}")
        
        # EMOJI DELETE DETECTION
        elif entry.action == discord.AuditLogAction.emoji_delete:
            if check_rate_limit(actor.id, emoji_delete_tracker, RATE_LIMITS['emoji_delete']['limit'], RATE_LIMITS['emoji_delete']['window']):
                emoji_delete_tracker[actor.id].clear()
                
                try:
                    await guild.ban(
                        actor,
                        reason=f"Anti-Nuke: Mass Emoji Deletion ({RATE_LIMITS['emoji_delete']['limit']}+ emojis in {RATE_LIMITS['emoji_delete']['window']}s)",
                        delete_message_days=1
                    )
                except discord.Forbidden:
                    logger.error(f"Missing permissions to ban {actor} from {guild.name}")
                except discord.HTTPException as e:
                    logger.error(f"Failed to ban {actor}: {e}")
                
                await send_mod_log(
                    guild,
                    "Anti-Nuke: Mass Emoji Deletion",
                    actor,
                    f"Emoji: {entry.target.name if entry.target else 'Unknown'}",
                    f"User banned for deleting {RATE_LIMITS['emoji_delete']['limit']}+ emojis in {RATE_LIMITS['emoji_delete']['window']} seconds.",
                    color=0xFF0000
                )
                logger.warning(f"Mass emoji deletion detected: {actor} banned from {guild.name}")
        
        # BOT ADD DETECTION - Whitelisted users and bypass role are immune
        elif entry.action == discord.AuditLogAction.bot_add:
            unauthorized_bot = entry.target
            
            if not unauthorized_bot or not getattr(unauthorized_bot, "bot", False):
                return
            
            # Whitelisted users and bypass role are completely immune
            if await is_whitelisted(actor, guild):
                await send_mod_log(
                    guild,
                    "Bot Addition (Whitelisted User)",
                    actor,
                    f"<@{unauthorized_bot.id}> ({unauthorized_bot.name})",
                    f"Whitelisted user added a bot to the server. Bot ID: {unauthorized_bot.id}",
                    color=0x00FF00  # Green for authorized
                )
                logger.info(f"Whitelisted user {actor} added bot {unauthorized_bot.name} to {guild.name}")
                return  # Don't punish
            
            # Not whitelisted - take action
            try:
                await actor.send("You are not authorized to add bots. This action has been logged.")
            except discord.HTTPException:
                pass
            
            try:
                await guild.kick(unauthorized_bot, reason="Unauthorized Bot")
                await guild.ban(actor, reason="Unauthorized Bot Added", delete_message_days=1)
            except discord.Forbidden:
                logger.error(f"Missing permissions to handle unauthorized bot in {guild.name}")
            except discord.HTTPException as e:
                logger.error(f"Failed to handle unauthorized bot: {e}")
            
            await send_mod_log(
                guild,
                "Unauthorized Bot",
                actor,
                f"<@{unauthorized_bot.id}> ({unauthorized_bot.name})",
                "Bot inviter banned and bot kicked.",
                color=0xFF0000
            )
            logger.warning(f"Unauthorized bot added: {actor} banned from {guild.name}")
                    
    except discord.Forbidden:
        logger.error(f"Missing permissions for audit log handler in {guild.name if guild else 'unknown'}")
    except Exception as e:
        logger.error(f"Error in on_audit_log_entry_create: {e}\n{traceback.format_exc()}")

# --- MESSAGE EVENT ---

@bot.event
async def on_message(message: discord.Message):
    """Handle messages with spam detection and anti-link filtering."""
    try:
        if message.author.bot:
            return
        
        # Ignore DMs
        if message.guild is None:
            return
        
        # Check whitelist first (bypass role and hardcoded users are immune)
        if await is_whitelisted(message.author, message.guild):
            await bot.process_commands(message)
            return
        
        uid = message.author.id
        
        # ANTI-LINK FILTERING
        if ANTI_LINK_ENABLED:
            links = extract_links(message.content)
            if links:
                # Check if any link is blocked
                blocked_links = [url for url in links if not is_allowed_link(url)]
                if blocked_links:
                    try:
                        await message.delete()
                        await message.author.timeout(
                            datetime.timedelta(minutes=1),
                            reason="Blocked link posted"
                        )
                        await message.channel.send(f"{message.author.mention} No blocked links allowed.", delete_after=5)
                        
                        await send_mod_log(
                            message.guild,
                            "Blocked Link Filter",
                            message.author,
                            message.channel.mention,
                            f"Blocked link(s) detected and removed: {', '.join(blocked_links[:3])}",
                            color=0xFFA500
                        )
                    except discord.Forbidden:
                        logger.error(f"Missing permissions to delete message in {message.guild.name}")
                    except discord.HTTPException as e:
                        logger.error(f"Failed to handle blocked link: {e}")
                    return
        
        # POLL SPAM
        if getattr(message, "poll", None):
            if check_rate_limit(uid, poll_tracker, RATE_LIMITS['poll']['limit'], RATE_LIMITS['poll']['window']):
                poll_tracker[uid].clear()
                try:
                    await asyncio.gather(
                        message.channel.purge(
                            limit=10,
                            check=lambda m: getattr(m, "poll", None) and m.author == message.author
                        ),
                        message.author.timeout(
                            datetime.timedelta(minutes=1),
                            reason="Mass Poll Spam"
                        ),
                        message.channel.send(f"stfu {message.author.mention}.")
                    )
                    await send_mod_log(
                        message.guild,
                        "Mass Poll Spam",
                        message.author,
                        message.channel.mention,
                        "Polls purged and user timed out.",
                        color=0xFFA500
                    )
                except discord.HTTPException:
                    pass
            return
        
        # TEXT SPAM
        if check_rate_limit(uid, spam_tracker, RATE_LIMITS['spam']['limit'], RATE_LIMITS['spam']['window']):
            spam_tracker[uid].clear()
            try:
                await asyncio.gather(
                    message.channel.purge(
                        limit=10,
                        check=lambda m: m.author == message.author
                    ),
                    message.author.timeout(
                        datetime.timedelta(minutes=1),
                        reason="Mass Spam"
                    ),
                    message.channel.send(f"stfu {message.author.mention}.")
                )
                await send_mod_log(
                    message.guild,
                    "Mass Spam",
                    message.author,
                    message.channel.mention,
                    "Messages purged and user timed out.",
                    color=0xFFA500
                )
            except discord.HTTPException:
                pass
            return
        
        await bot.process_commands(message)
        
    except Exception as e:
        logger.error(f"Error in on_message: {e}\n{traceback.format_exc()}")

# --- THREAD SPAM ---

@bot.event
async def on_thread_create(thread: discord.Thread):
    """Detect and prevent thread spam."""
    try:
        guild = thread.guild
        owner = thread.owner
        
        if not owner or owner.bot or await is_whitelisted(owner, guild):
            return
        
        uid = owner.id
        
        if check_rate_limit(uid, thread_tracker, RATE_LIMITS['thread']['limit'], RATE_LIMITS['thread']['window']):
            thread_tracker[uid].clear()
            try:
                await asyncio.gather(
                    thread.delete(),
                    owner.timeout(
                        datetime.timedelta(minutes=1),
                        reason="Mass Thread Spam"
                    ),
                    thread.parent.send(f"stfu {owner.mention}.")
                )
                await send_mod_log(
                    guild,
                    "Mass Thread Spam",
                    owner,
                    "Multiple Threads",
                    "User exceeded thread creation limits.",
                    color=0xFFA500
                )
            except discord.HTTPException:
                pass
    except Exception as e:
        logger.error(f"Error in on_thread_create: {e}")

# --- COMMANDS ---

@bot.command(name="scan")
async def scan(ctx):
    """Scan daily join/leave statistics."""
    try:
        today = datetime.datetime.now(datetime.timezone.utc).date()
        
        joins = len([t for t in join_history if t.date() == today])
        leaves = len([t for t in leave_history if t.date() == today])
        
        embed = discord.Embed(
            title="Server Daily Scan",
            color=0x2B2D31
        )
        embed.add_field(name="Users joined today", value=str(joins), inline=True)
        embed.add_field(name="Users left today", value=str(leaves), inline=True)
        embed.add_field(name="Net Change", value=f"{joins - leaves:+d}", inline=True)
        embed.set_footer(text=f"Requested by {ctx.author}")
        
        await ctx.send(embed=embed)
    except Exception as e:
        logger.error(f"Error in scan command: {e}")
        await ctx.send("Failed to scan. Check permissions.")

@bot.command(name="kill")
@commands.has_permissions(ban_members=True)
async def kill(ctx, target: discord.User):
    """Hard ban command with hierarchy check."""
    try:
        target_member = ctx.guild.get_member(target.id)
        
        if target_member:
            if ctx.author.top_role.position <= target_member.top_role.position:
                await ctx.send("You cannot ban this member (role hierarchy).")
                return
            
            me = ctx.guild.get_member(bot.user.id)
            if me and me.top_role.position <= target_member.top_role.position:
                await ctx.send("I cannot ban this member (bot hierarchy).")
                return
        
        await ctx.guild.ban(
            target,
            reason=f"Hardban: Security Kill Command by {ctx.author}",
            delete_message_days=1
        )
        
        await ctx.send(f"{target.mention} has been banned.")
        logger.info(f"Kill command executed by {ctx.author} on {target} in {ctx.guild.name}")
        
    except discord.Forbidden:
        await ctx.send("I don't have permission to ban this user.")
    except Exception as e:
        logger.error(f"Error in kill command: {e}")
        await ctx.send(f"Failed to ban user: {e}")

@kill.error
async def kill_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("You don't have permission to use this command.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("Usage: kin.kill @user")
    else:
        await ctx.send(f"Error: {error}")

@bot.command(name="call")
@rate_limit_command(limit=5, window=60)
@require_whitelist()
async def call(ctx, target: discord.User, *, message: str):
    """Direct message a user with logging."""
    try:
        message = message[:2000]
        if not message.strip():
            await ctx.send("Message cannot be empty.")
            return
        
        if target.bot:
            await ctx.send("Cannot DM bots.")
            return
        
        delivered = False
        delivery_status_details = "Message delivered successfully."
        
        try:
            await target.send(message)
            delivered = True
        except discord.Forbidden:
            delivery_status_details = "User has DMs disabled or blocked the bot."
        except discord.HTTPException as e:
            delivery_status_details = f"API error: {e}"
        
        embed = discord.Embed(
            title="Direct Message Execution Log",
            color=0x2B2D31,
            timestamp=discord.utils.utcnow()
        )
        embed.add_field(name="Target User", value=f"{target.mention} ({target.name})", inline=True)
        embed.add_field(name="Target ID", value=f"`{target.id}`", inline=True)
        embed.add_field(name="Executed By", value=f"{ctx.author.mention}", inline=False)
        embed.add_field(name="Status", value="DELIVERED" if delivered else "FAILED", inline=True)
        embed.add_field(name="Details", value=delivery_status_details, inline=True)
        embed.add_field(name="Message", value=f"```\n{message[:1000]}\n```", inline=False)
        embed.set_footer(text="Kinsec Security Core")
        
        log_channel = ctx.guild.get_channel(LOG_CHANNEL_ID)
        if log_channel:
            await log_channel.send(embed=embed)
        
        await ctx.send(f"Process complete. Status: **{'DELIVERED' if delivered else 'FAILED'}**.")
        
    except Exception as e:
        logger.error(f"Error in call command: {e}")
        await ctx.send(f"Error: {e}")

@bot.command(name="dmall")
@rate_limit_command(limit=1, window=300)
@require_whitelist()
async def dmall(ctx, *, message_text: str):
    """Mass DM all members with rate limiting."""
    try:
        message_text = message_text[:2000]
        if not message_text.strip():
            await ctx.send("Message cannot be empty.")
            return
        
        status_msg = await ctx.send("Initiating Mass DM broadcast...")
        
        targets = [m for m in ctx.guild.members if not m.bot]
        total_targets = len(targets)
        
        if total_targets == 0:
            await ctx.send("No members to DM.")
            return
        
        if total_targets > 100:
            await ctx.send(f"This will DM **{total_targets}** members. Continue? (yes/no)")
            
            def check(m):
                return m.author == ctx.author and m.channel == ctx.channel and m.content.lower() in ['yes', 'no']
            
            try:
                response = await bot.wait_for('message', timeout=30.0, check=check)
                if response.content.lower() == 'no':
                    await ctx.send("Broadcast cancelled.")
                    return
            except asyncio.TimeoutError:
                await ctx.send("Timed out. Broadcast cancelled.")
                return
        
        success_count = 0
        fail_count = 0
        failed_users = []
        
        for index, member in enumerate(targets):
            try:
                await member.send(message_text)
                success_count += 1
            except (discord.Forbidden, discord.HTTPException) as e:
                fail_count += 1
                if len(failed_users) < 10:
                    failed_users.append(f"{member.name}#{member.discriminator}")
            
            if (index + 1) % 5 == 0 or (index + 1) == total_targets:
                try:
                    await status_msg.edit(
                        content=(
                            f"Broadcasting: {index + 1}/{total_targets}\n"
                            f"Sent: {success_count}\n"
                            f"Failed: {fail_count}"
                        )
                    )
                except discord.HTTPException:
                    pass
            
            if (index + 1) < total_targets:
                await asyncio.sleep(2)
        
        report = f"Mass DM complete.\nSent: {success_count}\nFailed: {fail_count}"
        if failed_users:
            report += f"\n\nFailed users (first 10):\n{', '.join(failed_users)}"
        
        await ctx.send(report[:2000])
        
        await send_mod_log(
            ctx.guild,
            "Mass DM Broadcast",
            ctx.author,
            f"{success_count} Members",
            f"Sent message: '{message_text[:100]}...'",
            color=0x00FF00
        )
        
    except Exception as e:
        logger.error(f"Error in dmall command: {e}")
        await ctx.send(f"Error during broadcast: {e}")

# --- START BOT ---

if __name__ == "__main__":
    try:
        bot.run(BOT_TOKEN)
    except discord.LoginFailure:
        logger.critical("Invalid bot token. Please check your BOT_TOKEN environment variable.")
    except Exception as e:
        logger.critical(f"Failed to start bot: {e}\n{traceback.format_exc()}")
