from wiki.conf import settings
import collections

###############################
# ARTICLE PERMISSION HANDLING #
###############################
#
# All functions are:
#   can_something(article, user)
#      => True/False
#
# All functions can be replaced by pointing their relevant
# settings variable in wiki.conf.settings to a callable(article, user)

def can_read(article, user):
    if isinstance(settings.CAN_READ, collections.Callable):
        return settings.CAN_READ(article, user)
    else:
        # Deny reading access to deleted articles if user has no delete access
        article_is_deleted = article.current_revision and article.current_revision.deleted
        if article_is_deleted and not article.can_delete(user):
            return False
        
        # Check access for other users...
        if user.is_anonymous() and not settings.ANONYMOUS:
            return False
        elif article.other_read:
            return True
        elif user.is_anonymous():
            return  False
        if user == article.owner:
            return True
        if article.group_read:
            if article.group and user.groups.filter(id=article.group.id).exists():
                return True
        if article.can_moderate(user):
            return True
        return False
        
def can_write(article, user):
    if isinstance(settings.CAN_WRITE, collections.Callable):
        return settings.CAN_WRITE(article, user)
    # Check access for other users...
    if user.is_anonymous() and not settings.ANONYMOUS_WRITE:
        return False
    elif article.other_write:
        return True
    elif user.is_anonymous():
        return  False
    if user == article.owner:
        return True
    if article.group_write:
        if article.group and user and user.groups.filter(id=article.group.id).exists():
            return True
    if article.can_moderate(user):
        return True
    return False

def can_assign(article, user):
    if isinstance(settings.CAN_ASSIGN, collections.Callable):
        return settings.CAN_ASSIGN(article, user)
    return not user.is_anonymous() and user.has_perm('wiki.assign')

def can_assign_owner(article, user):
    if isinstance(settings.CAN_ASSIGN_OWNER, collections.Callable):
        return settings.CAN_ASSIGN_OWNER(article, user)
    return False

def can_change_permissions(article, user):
    if isinstance(settings.CAN_CHANGE_PERMISSIONS, collections.Callable):
        return settings.CAN_CHANGE_PERMISSIONS(article, user)
    return (
        not user.is_anonymous() and (
            article.owner == user or 
            user.has_perm('wiki.assign')
        )
    )

def can_delete(article, user):
    if isinstance(settings.CAN_DELETE, collections.Callable):
        return settings.CAN_DELETE(article, user)
    return not user.is_anonymous() and article.can_write(user)

def can_moderate(article, user):
    if isinstance(settings.CAN_MODERATE, collections.Callable):
        return settings.CAN_MODERATE(article, user)
    return not user.is_anonymous() and user.has_perm('wiki.moderate')

def can_admin(article, user):
    if isinstance(settings.CAN_ADMIN, collections.Callable):
        return settings.CAN_ADMIN(article, user)
    return not user.is_anonymous() and user.has_perm('wiki.admin')

